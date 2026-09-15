export const RULES_VERSION = '1.0.0';

const DEFINITIONS = [
  ['headers.csp', 'Content Security Policy', 'low', '실제 HTML 응답에 강제 적용 CSP 헤더가 있는지 확인합니다. 정책의 모든 우회 가능성이나 XSS 취약성을 판정하지 않습니다.', '서비스에 필요한 출처만 허용하는 CSP를 설정하고 Report-Only 정책을 검증한 뒤 강제 적용하세요.'],
  ['headers.frame-protection', 'Frame embedding protection', 'low', '강제 적용 frame-ancestors 또는 유효한 X-Frame-Options의 프레임 제한 설정을 확인합니다. 실제 클릭재킹 가능성은 별도 검토가 필요합니다.', "CSP frame-ancestors 'none' 또는 필요한 출처만 허용하는 정책을 사용하고 호환성이 필요하면 X-Frame-Options를 설정하세요."],
  ['headers.nosniff', 'Content type sniffing protection', 'low', 'X-Content-Type-Options: nosniff 설정을 확인합니다.', '올바른 Content-Type과 함께 X-Content-Type-Options: nosniff를 반환하세요.'],
  ['headers.hsts', 'HTTP Strict Transport Security', 'low', 'HTTPS 응답의 유효한 양수 max-age HSTS 설정을 확인합니다. HTTP 응답에는 적용되지 않습니다.', 'HTTPS 전환을 검증한 뒤 Strict-Transport-Security에 적절한 max-age를 설정하세요. 하위 도메인 포함 여부는 운영 범위를 검토하세요.'],
  ['cookies.flags', 'Cookie attribute review', 'low', '설정된 쿠키의 Secure(HTTPS), HttpOnly, SameSite 속성을 검토합니다. JavaScript 접근이 필요한 쿠키 등 용도에 따른 예외를 검토해야 합니다.', '민감한 세션 쿠키에 Secure, HttpOnly와 적절한 SameSite를 지정하세요. SameSite=None에는 Secure가 필요합니다.'],
  ['content.mixed-active-resources', 'HTTP active resource references', 'low', 'HTTPS HTML에 명시된 HTTP script, frame, object, embed, stylesheet 참조를 관찰합니다. 문자열 기반 보조 점검이며 브라우저의 실제 실행·차단 여부는 확인하지 않습니다.', '능동 리소스 참조를 HTTPS로 전환하고 브라우저에서 리디렉션, CSP 업그레이드 및 실제 로드를 확인하세요.'],
];

function readHeader(headers, name) {
  const value = Object.entries(headers || {}).find(([key]) => key.toLowerCase() === name)?.[1];
  return Array.isArray(value) ? value.join(', ') : typeof value === 'string' ? value : '';
}

function cspPolicies(value) {
  return value.split(',').filter(Boolean).map((policy) => {
    const directives = new Map();
    for (const directive of policy.split(';')) {
      const [name, ...sources] = directive.trim().split(/\s+/u);
      if (name && !directives.has(name.toLowerCase())) directives.set(name.toLowerCase(), sources);
    }
    return directives;
  });
}

function restrictiveAncestors(sources) {
  if (!sources?.length) return false;
  if (sources.length === 1 && sources[0] === "'none'") return true;
  return sources.every((source) => source === "'self'" ||
    /^(?:https?:\/\/)?(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]+)?(?:\/[^\s]*)?$/iu.test(source));
}

function attributes(tag) {
  const result = new Map();
  for (const match of tag.matchAll(/([^\s=<>"'`]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gu)) {
    if (!result.has(match[1].toLowerCase())) result.set(match[1].toLowerCase(), match[2] ?? match[3] ?? match[4]);
  }
  return result;
}

export function analyzeResponse(response) {
  const headers = response.headers || {};
  const body = typeof response.body === 'string' ? response.body : '';
  const statusOk = Number.isInteger(response.status) && response.status >= 200 && response.status < 300;
  const mime = readHeader(headers, 'content-type').split(';')[0].trim().toLowerCase();
  const html = ['text/html', 'application/xhtml+xml'].includes(mime);
  const encoded = !['', 'identity'].includes(readHeader(headers, 'content-encoding').trim().toLowerCase());
  const https = /^https:\/\//iu.test(response.url || '');
  const observations = [];
  const limitations = [];
  const empty = body.trim().length === 0;
  if (empty) limitations.push('빈 응답은 이전 페이지와 비교할 근거가 부족하므로 정상 또는 조치 완료로 판정하지 않습니다.');
  if (!statusOk) limitations.push(`HTTP ${response.status ?? 'unknown'} 응답은 성공한 페이지로 판정하지 않습니다.`);
  if (response.truncated) limitations.push('응답 본문이 크기 제한으로 잘렸습니다. 누락된 내용과 조치 완료 여부를 판정할 수 없습니다.');
  if (!html) limitations.push(`HTML 응답이 아니므로 HTML 구성 점검을 평가하지 않습니다 (${mime || 'Content-Type 없음'}).`);
  if (encoded) limitations.push('압축된 응답을 해제하지 않았으므로 HTML 본문을 평가하지 않습니다.');
  if (limitations.length) observations.push({ kind: 'assessment-limitation', description: limitations.join(' ') });
  if (response.truncated) observations.push({ kind: 'evidence-integrity', description: 'sha256는 수신·보관한 제한된 원문 바이트의 해시이며 전체 응답의 해시가 아닙니다.' });
  const assessable = statusOk && !response.truncated && !empty;
  const htmlAssessable = assessable && html && !encoded;
  const unknownReason = limitations.join(' ') || '이 응답에 적용되는 점검이 아닙니다.';
  const checks = DEFINITIONS.map(([ruleId, title, severity, description, remediation]) =>
    ({ ruleId, title, outcome: 'unknown', severity, description, remediation, evidence: unknownReason }));
  const byId = new Map(checks.map((check) => [check.ruleId, check]));
  const set = (ruleId, condition, evidence) => Object.assign(byId.get(ruleId), { outcome: condition ? 'pass' : 'fail', evidence });

  if (htmlAssessable) {
    const csp = readHeader(headers, 'content-security-policy').trim();
    const policies = cspPolicies(csp);
    set('headers.csp', Boolean(csp), `Enforced Content-Security-Policy: ${csp ? 'present (policy strength not fully assessed)' : 'absent'}.`);
    const ancestors = policies.filter((policy) => policy.has('frame-ancestors')).map((policy) => policy.get('frame-ancestors'));
    const xfo = readHeader(headers, 'x-frame-options').trim().toUpperCase();
    const xfoValid = ['DENY', 'SAMEORIGIN'].includes(xfo);
    // Enforced frame-ancestors takes precedence over X-Frame-Options in supporting browsers.
    const frameProtected = ancestors.length ? ancestors.some(restrictiveAncestors) : xfoValid;
    set('headers.frame-protection', frameProtected, `Enforced frame-ancestors: ${ancestors.length ? (frameProtected ? 'restricted sources observed' : 'restriction not established') : 'absent'}; X-Frame-Options: ${xfoValid ? xfo : (xfo ? 'unrecognized or conflicting value' : 'absent')}.`);
    const nosniff = readHeader(headers, 'x-content-type-options').trim().toLowerCase() === 'nosniff';
    set('headers.nosniff', nosniff, `X-Content-Type-Options nosniff: ${nosniff ? 'present' : 'absent or invalid'}.`);
    if (https) {
      const hsts = readHeader(headers, 'strict-transport-security');
      const matches = [...hsts.matchAll(/(?:^|;)\s*max-age\s*=\s*(?:"(\d+)"|(\d+))\s*(?=;|$)/giu)];
      const maxAge = matches.length === 1 ? Number(matches[0][1] ?? matches[0][2]) : NaN;
      const valid = Number.isSafeInteger(maxAge) && maxAge > 0;
      set('headers.hsts', valid, `HTTPS; HSTS with one positive max-age: ${valid ? 'present' : 'absent or invalid'}.`);
    } else byId.get('headers.hsts').evidence = 'HSTS is evaluated only on HTTPS responses; HTTP transport requires separate review.';

    if (https) {
      const tags = [];
      const markup = body.replace(/<!--[\s\S]*?-->/gu, '')
        .replace(/(<(script|style|textarea|title)\b(?:[^>"']|"[^"]*"|'[^']*')*>)[\s\S]*?(?:<\/\2\s*>|$)/giu, '$1');
      for (const match of markup.matchAll(/<(script|iframe|object|embed|link)\b(?:[^>"']|"[^"]*"|'[^']*')*>/giu)) {
        const kind = match[1].toLowerCase();
        const attrs = attributes(match[0]);
        if (kind === 'link' && !/(?:^|\s)(?:stylesheet|import)(?:\s|$)/iu.test(attrs.get('rel') || '')) continue;
        const source = attrs.get(kind === 'object' ? 'data' : kind === 'link' ? 'href' : 'src') || '';
        if (/^http:\/\//iu.test(source.trim())) tags.push(kind);
      }
      set('content.mixed-active-resources', tags.length === 0, tags.length
        ? `${tags.length} explicit HTTP active-resource reference(s); tag types: ${[...new Set(tags)].join(', ')}. Advisory only; resource execution was not tested.`
        : 'No literal HTTP active-resource reference observed in the captured static HTML. Dynamic, entity-encoded and CSS references are outside this check.');
    } else byId.get('content.mixed-active-resources').evidence = 'Mixed content is evaluated only for HTTPS HTML responses.';

  }

  if (assessable && !encoded && (html || ['text/javascript', 'application/javascript', 'text/css'].includes(mime))) {
    const sourceMapComments = [...body.matchAll(/(?:\/\/[#@]\s*sourceMappingURL\s*=\s*[^\r\n<]+|\/\*[#@]\s*sourceMappingURL\s*=[\s\S]*?\*\/)/gu)];
    if (sourceMapComments.length) observations.push({ kind: 'source-map-reference', count: sourceMapComments.length, assessment: 'reference_only',
      description: 'sourceMappingURL 주석을 관찰했습니다. 맵 파일을 요청하지 않았으며 접근 가능성·원본 코드 노출 여부는 확인되지 않았습니다.' });
  }

  if (assessable) {
    const rawCookies = Object.entries(headers).find(([key]) => key.toLowerCase() === 'set-cookie')?.[1];
    const cookies = Array.isArray(rawCookies) ? rawCookies : typeof rawCookies === 'string' && rawCookies ? [rawCookies] : [];
    if (!cookies.length) byId.get('cookies.flags').evidence = 'No Set-Cookie header observed; existing browser cookies were not inspected.';
    else {
      let allFlags = true;
      const details = cookies.map((cookie, index) => {
        const attrs = new Map(String(cookie).split(';').slice(1).map((part) => {
          const [name, ...value] = part.trim().split('=');
          return [name.toLowerCase(), value.join('=').toLowerCase()];
        }));
        const secure = attrs.has('secure');
        const httpOnly = attrs.has('httponly');
        const sameSite = attrs.get('samesite');
        const sameSiteValid = ['strict', 'lax', 'none'].includes(sameSite);
        allFlags &&= (!https || secure) && httpOnly && sameSiteValid && (sameSite !== 'none' || secure);
        return `Cookie #${index + 1}: Secure=${secure ? 'yes' : 'no'}, HttpOnly=${httpOnly ? 'yes' : 'no'}, SameSite=${sameSiteValid ? sameSite : 'absent/invalid'}`;
      });
      set('cookies.flags', allFlags, `${details.join('; ')}. Cookie names and values omitted. Application-specific exceptions require review.`);
    }
  }
  return { checks, observations };
}
