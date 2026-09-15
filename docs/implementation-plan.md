# PenTri Local v1.20 개발 계획

기준일: 2026-09-11. 이번 사용자 요청을 우선하며 `pentri-v1.20-requirements.md`는 이전 요구사항 원문으로 보존한다. 이 계획의 구현 선택은 검증 가능한 개발 기준이며 사용자의 모든 제품 결정을 확정했다는 의미는 아니다.

## 목표와 첫 구현 범위

최종 목표는 승인된 웹 진단의 수집 → 분석 → 판단 → 증적·로그 → 보고서 → 개선 → 이행 확인을 연결하는 것이다. 첫 버전은 **내부망·외부망 진단용 독립 로컬 서버 + 브라우저 탭 UI + 설치된 Ollama 모델**로 이 흐름을 구현한다. 확장 프로그램은 명시적으로 연 대상의 관찰 자료를 JSON으로 전달하는 선택 수집기다. 스토어 등록은 후속으로 둔다.

웹 취약점 전체의 완전 자동 확정은 현재 완료 기준으로 삼을 수 없다. 접근제어·업무로직·실제 악용 가능성은 계정과 환경별 검증이 필요하다. 첫 버전은 HTTP 응답의 제한된 구성 점검을 자동화하고 관찰 결과, AI 의견, 검토자 판단을 별도로 기록한다. 자동 재검사에서 사라진 항목은 `not_observed`로 표시하며 곧바로 조치 완료로 확정하지 않는다.

## 구조 결정

- Node.js 24 내장 HTTP, SQLite, 테스트 러너를 사용한다. 앱 런타임 npm 외부 의존성 없이 폐쇄망 반입을 단순화한다. Node SQLite의 실험적 상태는 알려진 제약이다.
- 서버는 `127.0.0.1`에만 바인딩하고 Host/Origin 검사와 세션 토큰으로 로컬 API를 보호한다. 브라우저 UI는 같은 origin에서 제공한다.
- 명시적인 프로젝트 origin과 정확한 GET 경로 목록을 실행 전에 표시한다. 기본 private 정책은 공인 IP를 차단하고, 사용자가 public 정책을 지정한 프로젝트만 명시된 외부 origin을 허용한다. 모든 정책에서 link-local/metadata, reserved IP, 서버 자체와 Ollama 서비스는 차단한다. DNS 검증 결과를 실제 소켓에 고정하고 redirect는 자동 추적하지 않는다.
- 요청 수·응답 크기·시간·간격을 제한한다. AI 출력으로 URL, 명령, 도구 실행을 생성하거나 승인하지 않는다. HTML/JS는 실행하지 않으며 링크를 자동 추적하지 않는다.
- SQLite에 프로젝트, 실행, 마스킹된 증적, 규칙별 검사 결과, 발견 사항, 검토, AI 의견, 감사 이벤트를 남긴다. AI 호출과 내보내기는 원문보다 최소화된 자료를 사용한다.
- Ollama 주소는 서버 설정의 loopback endpoint로 제한한다. 로컬 설치 모델 목록/메타데이터를 검증하고 cloud 모델을 거부한다. 모델 자동 다운로드와 상용 LLM 연결은 첫 구현에서 제외한다.
- HTML/JSON 보고서에 범위, 요청 상태, 근거, 판단 주체, 조치안, 재검사 상태를 포함한다. 실패·접근불가·검사 누락은 정상 판정으로 취급하지 않는다.

## 모듈 계약

`src/network.mjs`: `validatePlan({origin, paths, networkPolicy?}, {blockedPorts?})`, `requestTarget(url, {signal, maxBytes?, timeoutMs?, blockedPorts?, networkPolicy?})`. 반환 응답: `{url,status,headers,body,bytes,truncated,sha256,remoteAddress,durationMs}`. 네트워크 실패는 예외. origin은 HTTP(S), 경로는 query/fragment 없는 명시적 절대 경로 최대 20개. private 정책은 loopback과 RFC1918/IPv6 ULA만, public 정책은 정상 공인 IP도 허용.

`src/analyzer.mjs`: `analyzeResponse(response)` → `{checks, observations}`. 각 check: `{ruleId,title,outcome:'pass'|'fail'|'unknown',severity,description,remediation,evidence}`. evidence는 문자열. 관찰은 JSON. 근거 없는 취약성 확정 금지. 잘린/실패 응답의 제한을 명시한다.

`src/redact.mjs`: `redact(value)` → 재귀적으로 마스킹한 JSON 호환 값. 원문 해시는 증적 무결성용, 마스킹 후 해시는 보관 자료 검증용으로 구별한다.

`src/store.mjs`, `src/runner.mjs`, `src/ollama.mjs`, `src/server.mjs`: 저장, 순차 실행/중단/재검사, 스키마 검증된 AI 의견, 인증 API.

UI API (JSON): `GET /api/session` → `{token}`; 모든 나머지 API는 `X-Pentri-Token` 필요. `GET /api/status`, `GET/POST /api/projects`, `GET /api/projects/:id`, `POST /api/projects/:id/runs` `{approved:true,ai:false,model?:string}`, `GET /api/runs/:id`, `POST /api/runs/:id/cancel`, `POST /api/findings/:id/review` `{status:'confirmed'|'dismissed'|'fixed'|'candidate',note}`, `POST /api/runs/:id/analyze` `{model}`, `GET /api/projects/:id/report?format=json|html`, `POST /api/projects/:id/import` `{snapshot}`, `DELETE /api/projects/:id`.

Project: `{id,name,origin,paths,networkPolicy,createdAt}`. Detail: `{project,runs,findings,evidence,events,imports}`. Run: `{id,projectId,status:'queued'|'running'|'completed'|'cancelled'|'failed'|'interrupted',startedAt,finishedAt,error,progress,checks,ai}`. Finding: `{id,projectId,ruleId,url,title,severity,status,description,remediation,evidenceId,firstSeen,lastSeen,retestStatus,reviewNote}`. Evidence: `{id,runId,url,status,headers,excerpt,sha256,storedSha256,bytes,truncated,createdAt}`. `GET /api/status` → `{version,ollama:{available,models:[{name}],error?},limits:{...}}`.

## 개발 시작 전 검토

첨부 코드 정적 분석(`legacy-audit.md`)과 독립 위협 검토(`design-review.md`)를 수행한다. 설계에서 발견한 GET의 상태 변경 가능성, DNS 재검사, 로컬 API 위조, cloud proxy 가능성을 구현·회귀 테스트에 반영한다. 기존 코드의 광범위한 권한과 실행 계층은 새 코어에 복사하지 않는다.

## 수용 기준

1. 재시작해도 프로젝트와 실행/증적/검토가 복원된다. 실행 중 재시작은 interrupted로 기록한다.
2. 명시 범위 밖 요청, private 정책에서 공인 IP, metadata, 사용자정보 URL, redirect 추적, 초과 응답, 무기한 대기를 제한한다. 취소 후 후속 요청이 실행되지 않는다.
3. 로컬 fixture의 보안 설정 변경 전후 검사와 보고서가 일치한다. 403/500/잘린 응답을 조치 완료로 판정하지 않는다.
4. 인증·Origin/Host 검사, XSS 출력 이스케이프, 비밀정보 마스킹, 데이터 삭제와 감사 무결성을 검증한다.
5. mock Ollama에서 정상/비정상 JSON, 존재하지 않는 근거 참조, cloud 모델 거부, timeout을 검증한다. 실제 로컬 모델 검증 여부는 별도로 명시한다.
6. 브라우저 UI에서 프로젝트 생성 → 실행 → 근거 확인 → 판단 → 내보내기 → 재검사를 검증한다. 테스트한 OS/브라우저와 미검증 환경을 구별한다.

## 후속 단계와 완료 조건

| 단계 | 결과 | 진입/완료 조건 |
| --- | --- | --- |
| M1 현재 | 로컬 HTTP 구성 점검, 증적·로그·보고서·재검사, Ollama 의견, 선택 확장 수집 | 위 수용 기준과 알려진 제약 공개 |
| M2 분석 확대 | 인증 세션, DOM/JS 파서, 정확한 기술 버전, source map, CVE 오프라인 DB | 라이선스 확인, 규칙별 양성/음성 corpus, 대상·문서 ID 연결 |
| M3 통제된 능동 진단 | 점검별 실행 계획과 검증기, staging fixture, 승인·복구·중단 | 상태 변경·부하 등급, 회귀 테스트, 오탐/미탐 평가 통과 |
| M4 운영 자동화 | 스케줄, 조직별 보고서, 증적 이미지 편집, 이행 업무/담당자 연결 | 보존/암호화/권한/복구 요구 확정, 실제 사용자 평가 |
| M5 배포 확대 | Windows/macOS 패키지, 상용 LLM 옵션, 스토어 준비 | 외부 전송 정책, 배포 서명, 라이선스·스토어 정책 검토 |

기존 Cipher, CheatSheet, 문구함, 전체 recon 개선 요구는 M2 이후 이관 backlog다. 이전 문서의 기능이 모두 새 버전에 들어갔다고 표시하지 않는다.

## 근거

- [Ollama 구조화 출력](https://docs.ollama.com/capabilities/structured-outputs): JSON schema를 제공해도 앱에서 다시 구조와 참조를 검증한다.
- [Ollama FAQ](https://docs.ollama.com/faq): `OLLAMA_NO_CLOUD=1`로 cloud 기능을 끌 수 있다. 실제 서버 설정과 방화벽 통제는 배포 검증 항목이다.
- [Chrome action](https://developer.chrome.com/docs/extensions/reference/api/action): 사용자 클릭을 확장 도구 탭 진입점으로 사용한다.

이 문서의 구조·단계는 위 자료와 코드 분석을 바탕으로 한 본 프로젝트의 설계 판단이다.

## 실행 환경 보정 (사용자 답변)

사용자는 내부망과 외부망 모두의 진단, Windows PC 중심 운영과 Mac 지원을 요청했다. 동일 Node 코어를 두 OS에서 실행하도록 구성하고 CI에 Windows/macOS/Linux 테스트를 둔다. 현재 기기의 실제 검증과 CI 설정만 완료한 OS를 구별한다. AI 처리 위치는 진단망과 독립적으로 로컬에 유지한다.

## 실행 형태 보정 (2026-09-15)

사용자는 Chrome 또는 ZIP 구조에 국한되지 않는 Windows/Mac UI 프로그램과 휴대 미니PC 운용을 요청했다. M1은 독립 서버/브라우저 UI, PC 런처와 OS별 Node 런타임 포함 휴대용 폴더, 미니PC SSH 터널 운용을 제공한다. 단일 exe와 네이티브 창/서명된 설치 프로그램은 후속 단계이며 현재 구현으로 표시하지 않는다. 확장은 선택 수집기만 담당한다.
