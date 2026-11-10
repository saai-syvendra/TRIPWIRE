"""
Fixed vocabularies shared by the candidate generator and the verifier: comparison operators, environment
query APIs, file and tool tests, sinks, notable paths and value aliases, and the categories they map to.
"""
from __future__ import annotations

import re

NEGATE = {"==": "!=", "!=": "==", "in": "not_in", "not_in": "in", "truthy": "falsy", "falsy": "truthy",
          ">": "<=", "<": ">=", ">=": "<", "<=": ">", "exists": "not_exists", "not_exists": "exists",
          "startswith": "not_startswith", "not_startswith": "startswith", "includes": "not_includes",
          "not_includes": "includes", "regex": "not_regex", "not_regex": "regex"}
MIRROR = {">": "<", "<": ">", ">=": "<=", "<=": ">=", "==": "==", "!=": "!="}
JS_CMP = {"===": "==", "==": "==", "!==": "!=", "!=": "!=", "<": "<", ">": ">", "<=": "<=", ">=": ">="}
PY_CMP = {"==": "==", "!=": "!=", "<>": "!=", "<": "<", ">": ">", "<=": "<=", ">=": ">=", "in": "in",
          "not in": "not_in", "is": "==", "is not": "!="}
STRIP_METHODS = {"toLowerCase", "toUpperCase", "toLocaleLowerCase", "toLocaleUpperCase", "trim", "toString",
                 "normalize", "lower", "upper", "casefold", "strip", "lstrip", "rstrip", "title"}

CI_VARS = {"CI", "CONTINUOUS_INTEGRATION", "BUILD_NUMBER", "BUILD_ID", "RUN_ID", "GITHUB_ACTIONS",
           "GITHUB_WORKFLOW", "GITLAB_CI", "TRAVIS", "CIRCLECI", "JENKINS_URL", "JENKINS_HOME", "BUILDKITE",
           "TF_BUILD", "CODEBUILD_BUILD_ID", "TEAMCITY_VERSION", "BITBUCKET_BUILD_NUMBER", "DRONE", "APPVEYOR",
           "NETLIFY", "VERCEL", "SEMAPHORE", "HEROKU_TEST_RUN_ID", "BUDDY", "CI_NAME"}
ENV_CATEGORY = {**{v: "hostname" for v in ("COMPUTERNAME", "HOSTNAME", "USERDOMAIN")},
                **{v: "username" for v in ("USER", "USERNAME", "LOGNAME")},
                **{v: "home_or_path" for v in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
                                               "TEMP", "TMP", "TMPDIR", "PATH", "PWD")},
                **{v: "locale_language" for v in ("LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES")},
                "TZ": "timezone"}
HOME_VARS = {"HOME", "USERPROFILE"}

QUERIES = {
    "js": [(re.compile(p), c) for p, c in (
        (r"(process\.platform|os\.platform\(\)|os\.type\(\)|os\.release\(\)|os\.version\(\))$", "os"),
        (r"(process\.arch|os\.arch\(\)|os\.machine\(\))$", "arch"),
        (r"os\.hostname\(\)$", "hostname"),
        (r"(os\.userInfo\(\)\.uid|process\.gete?[ug]id\(\))$", "privilege"),
        (r"os\.userInfo\(\)(\.username)?$", "username"),
        (r"(os\.homedir\(\)|os\.userInfo\(\)\.homedir|process\.cwd\(\)|__dirname|__filename|os\.tmpdir\(\))$",
         "home_or_path"),
        (r"(Intl\.DateTimeFormat\(\)\.resolvedOptions\(\)\.timeZone|new Date\(\)\.getTimezoneOffset\(\))$",
         "timezone"),
        (r"(Intl\.DateTimeFormat\(\)\.resolvedOptions\(\)(\.locale)?|navigator\.languages?)$", "locale_language"),
        (r"(Date\.now\(\)|new Date\(\)(\.get\w+\(\))?)$", "time_date"),
        (r"(os\.uptime\(\)|process\.uptime\(\))$", "uptime"),
        (r"(os\.cpus\(\)(\.length)?|os\.totalmem\(\)|os\.freemem\(\)|os\.availableParallelism\(\))$", "hardware"),
        (r"(process\.version|process\.versions(\.\w+)?)$", "runtime_version"),
        (r"os\.networkInterfaces\(\)", "ip_or_geo_local"),
        (r"process\.env$", "env_var"),
    )],
    "py": [(re.compile(p), c) for p, c in (
        (r"(sys\.platform|os\.name|platform\.(system|platform|release|version|uname|win32_ver|mac_ver)\(\)"
         r"|os\.uname\(\)(\.sysname)?|platform\.uname\(\)\.system)$", "os"),
        (r"(platform\.(machine|architecture|processor)\(\)|os\.uname\(\)\.machine)", "arch"),
        (r"(socket\.gethostname\(\)|platform\.node\(\)|os\.uname\(\)\.nodename|socket\.getfqdn\(\))$", "hostname"),
        (r"(getpass\.getuser\(\)|os\.getlogin\(\)|pwd\.getpwuid\(\))", "username"),
        (r"(os\.path\.expanduser\(\)|pathlib\.Path\.home\(\)|os\.getcwd\(\)|__file__|pathlib\.Path\.cwd\(\))$",
         "home_or_path"),
        (r"locale\.(getdefaultlocale|getlocale)\(\)", "locale_language"),
        (r"time\.(tzname|timezone|altzone)", "timezone"),
        (r"(datetime\.(datetime\.)?(now|today|utcnow)\(\)|datetime\.date\.today\(\)|time\.time\(\)"
         r"|time\.localtime\(\))", "time_date"),
        (r"(psutil\.boot_time\(\)|time\.monotonic\(\))", "uptime"),
        (r"(os\.cpu_count\(\)|multiprocessing\.cpu_count\(\)|psutil\.(cpu_count|virtual_memory|disk_usage)\(\)"
         r"|uuid\.getnode\(\))", "hardware"),
        (r"(os\.gete?uid\(\)|ctypes\.windll\.shell32\.IsUserAnAdmin\(\))$", "privilege"),
        (r"(sys\.version_info|sys\.version$|platform\.python_version\(\))", "runtime_version"),
        (r"psutil\.(process_iter|pids)\(\)", "process_list"),
        (r"socket\.gethostbyname\(\)", "ip_or_geo_local"),
        (r"os\.environ$", "env_var"),
    )],
}
FILE_TESTS = {"js": {"fs.existsSync", "fs.statSync", "fs.lstatSync", "fs.accessSync", "fs.exists"},
              "py": {"os.path.exists", "os.path.isfile", "os.path.isdir", "os.path.lexists", "os.path.islink",
                     "os.access"}}
TOOL_TESTS = {"js": {"which.sync", "which", "commandExists.sync", "commandExistsSync", "hasbin.sync"},
              "py": {"shutil.which", "distutils.spawn.find_executable"}}
ENV_GETTERS = {"os.environ.get", "os.getenv", "os.environ.__contains__"}
SINKS = {
    "js": [(re.compile(p), k) for p, k in (
        (r"(child_process\.\w+|shelljs\.exec|execa(\.\w+)?|cross-spawn|Bun\.(\$|spawn\w*)|Deno\.(run|Command))\(\)$", "exec"),
        (r"(https?\.(request|get)|net\.(connect|createConnection)|tls\.connect|dgram\.createSocket|axios(\.\w+)?"
         r"|fetch|node-fetch|got(\.\w+)?|request(\.\w+)?|needle(\.\w+)?|superagent(\.\w+)?|dns\.\w+"
         r"|new (WebSocket|ws|net\.Socket|XMLHttpRequest))\(\)$", "network"),
        (r"fs(\.promises)?\.(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|copyFile"
         r"|copyFileSync|rename|renameSync|chmod\w*|symlink\w*|mkdir\w*)\(\)$", "fs_write"),
        (r"fs(\.promises)?\.(unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync)\(\)$", "fs_delete"),
        (r"fs(\.promises)?\.(readFile|readFileSync|readdir|readdirSync|createReadStream)\(\)$", "fs_read"),
        (r"(eval|Function|new Function|vm\.\w+|new vm\.Script)\(\)$", "eval"),
        (r"atob\(\)$", "decode"),
    )],
    "py": [(re.compile(p), k) for p, k in (
        (r"(subprocess\.\w+|os\.(system|popen|startfile|exec\w*|spawn\w*)|commands\.\w+|pty\.spawn)\(\)$", "exec"),
        (r"(urllib\.request\.(urlopen|urlretrieve)|urllib2\.urlopen|urllib\.urlopen|requests(\.\w+)?"
         r"|httpx(\.\w+)?|http\.client\.\w+|socket\.(socket|create_connection)|aiohttp\.\w+|smtplib\.\w+"
         r"|ftplib\.\w+)\(\)$", "network"),
        (r"(shutil\.(copy\w*|move)|os\.(rename|replace|makedirs|mkdir|chmod)|pathlib\.Path\(\)\.write_\w+)\(\)$",
         "fs_write"),
        (r"(os\.(remove|unlink|rmdir)|shutil\.rmtree|pathlib\.Path\(\)\.unlink)\(\)$", "fs_delete"),
        (r"(exec|eval|compile|__import__)\(\)$", "eval"),
        (r"(base64\.\w*decode|codecs\.decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|binascii\.unhexlify"
         r"|pickle\.loads)\(\)$", "decode"),
    )],
}
TARGET_PATHS = re.compile(
    r"(^|[/\\%~])\.env\b|\.ssh|id_rsa|discord|google[/\\]chrome|chrome[/\\]user data|brave|microsoft[/\\]edge"
    r"|opera|mozilla|firefox|local storage|leveldb|exodus|electrum|atomic|metamask|phantom|wallet|nkbihfbeogae"
    r"|\.npmrc|\.pypirc|\.aws|\.kube|\.docker[/\\]config|\.git-credentials|\.gitconfig|telegram|tdata|keychain"
    r"|_history|/usr/src/app", re.I)
SANDBOX_PATHS = re.compile(r"\.dockerenv|vbox|virtualbox|vmware|qemu|sandboxie|sbiedll|cuckoo|/proc/self/cgroup"
                           r"|/sys/class/dmi|/proc/1/cgroup", re.I)
OS_VALUES = {"win32": "win32", "nt": "win32", "windows": "win32", "windows_nt": "win32", "win": "win32",
             "win64": "win32", "cygwin": "win32", "msys": "win32", "darwin": "darwin", "mac": "darwin",
             "macos": "darwin", "osx": "darwin", "linux": "linux", "linux2": "linux", "posix": "linux",
             "freebsd": "freebsd", "openbsd": "openbsd", "sunos": "sunos", "aix": "aix", "android": "android"}
ARCH_VALUES = {"x64": "x64", "amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64", "ia32": "ia32",
               "x86": "ia32", "i386": "ia32", "i686": "ia32", "arm": "arm"}
OS_APIS = re.compile(r"process\.platform|os\.platform\(\)|os\.type\(\)|sys\.platform|os\.name|platform\.system\(\)"
                     r"|platform\.platform\(\)|platform\.uname\(\)")
PATH_JOINS = ("path.join", "path.resolve", "path.posix.join", "path.win32.join", "os.path.join", "posixpath.join",
              "ntpath.join")
# A string that could name a package file: no spaces, no scheme (":" is excluded), at least a dot or a slash.
PATH_LIKE = re.compile(r"^[\w@./\\-]{1,260}$")
# Calls that only read a file's content; a path handed to one of these is data, not a launch target.
READ_CALLS = re.compile(r"^(open|io\.open|codecs\.open|fs(\.promises)?\.(readFile|readFileSync|createReadStream)"
                        r"|.*\.read_text|.*\.read_bytes)\(\)$")
# Containers a literal can sit in on its way to the call that consumes it.
ARG_WRAPPERS = {"arguments", "argument_list", "parenthesized_expression", "binary_expression", "binary_operator",
                "concatenated_string", "template_string", "template_substitution"}


# Secrets a user sets for themselves (NPM_TOKEN, GITHUB_TOKEN, AWS keys): never installer variables, whatever
# their prefix.
CREDENTIAL_VARS = re.compile(r"TOKEN|SECRET|PASSW|AUTH|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL", re.I)


def env_category(name: str) -> str:
    if name in CI_VARS:
        return "ci_marker"
    if CREDENTIAL_VARS.search(name):
        return "env_var"
    if name.lower().startswith(("npm_", "yarn_", "pnpm_", "bun_")) or name == "INIT_CWD":
        return "package_manager"
    return ENV_CATEGORY.get(name, "env_var")


def path_category(path) -> str:
    p = str(path)
    if SANDBOX_PATHS.search(p):
        return "vm_sandbox_artifact"
    if TARGET_PATHS.search(p):
        return "target_artifact"
    return "file_or_dir_exists"


# Commands whose output or exit status, when tested, probe the environment (argv joined with spaces).
EXEC_PROBES = [(re.compile(p, re.I), c) for p, c in (
    (r"\bsudo\s+-n\b|\bid\s+-u\b(?!n)|\bnet\s+session\b|\bfltmc\b|\bwhoami\s+/priv\b", "privilege"),
    (r"\bwhoami\b|\bid\s+-un\b|\becho\s+\$USER\b", "username"),
    (r"\b(ps|tasklist|pgrep|pidof)\b", "process_list"),
    (r"^\s*(which|where|command\s+-v|type)\b|\bGet-Command\b", "installed_tool"),
    (r"\b(systemd-detect-virt|dmidecode|virt-what|vboxmanage|vmware-checkvm|lscpu)\b|\bwmic\s+(bios|computersystem)"
     r"|/sys/class/dmi|/proc/1/cgroup|/proc/self/cgroup|sysctl\s+(-n\s+)?(hw\.model|machdep)", "vm_sandbox_artifact"),
    (r"^\s*hostname\b|\bscutil\s+--get\s+computername\b", "hostname"),
    (r"\buname\b|\bsw_vers\b|\bver\b|/etc/os-release", "os"),
    (r"^\s*(ping|nslookup|dig|host|getent\s+hosts|curl|wget|nc)\b|&&\s*(ping|curl|wget)\b", "network_reachability"),
    (r"\blocale\b|AppleLocale|\bGet-Culture\b", "locale_language"),
    (r"\b(nproc|free|df)\b|\bsysctl\s+(-n\s+)?hw\.(ncpu|memsize)", "hardware"),
    (r"\bgit\s+config\b|\bnpm\s+(whoami|config\s+get)\b|\bgh\s+auth\b", "target_artifact"),
)]
# Calls that, as the first statement of a try body, probe for a file, module or command: success takes one
# branch, the handler the other.
TRY_PROBES = {
    "js": {"fs.readFileSync", "fs.statSync", "fs.lstatSync", "fs.accessSync", "fs.readdirSync", "fs.openSync",
           "require"},
    "py": {"open", "io.open", "os.stat", "os.lstat", "os.listdir", "os.scandir", "os.open", "__import__",
           "importlib.import_module"},
}
