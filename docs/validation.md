# 검증 기록 — v1.20 alpha

검증일: 2026-09-15. 개발·실행 환경: macOS arm64, Apple M2, RAM 16 GiB, Node 24.14.1, Ollama 0.31.2, 설치된 Google Chrome. 실제 운영 대상이나 외부 서비스에 진단 요청을 보내지 않았다.

## 실행 결과

| 구분 | 결과 | 근거/한계 |
| --- | --- | --- |
| 원본 분석 | ZIP 16개 파일 정적 분석 | 실행하지 않음. `legacy-audit.md` 파일/행 근거 |
| 구문·manifest | 통과 | `npm run check` |
| 단위·통합 회귀 | 46개 통과 | `npm test`; 네트워크·규칙·Ollama mock·API·재검사·저장·마스킹·선택 수집기 |
| 실제 브라우저 | 통과 | `npm run test:browser`; 임시 독립 Chrome 프로필, 합성 HTTP 대상 |
| 실제 Ollama | 단일 합성 관찰 구조화 응답 통과 | 아래 별도 결과. 모델 품질 검증 완료는 아님 |
| Windows/macOS/Linux CI | 세 OS 테스트·휴대용 빌드 통과 | [코드 ba38fa6 검증 실행](https://github.com/O-SQZ/pentri/actions/runs/34956534621). Windows 실제 데스크톱 UI와 미니PC 실기 검증은 별도 |
| 미니PC·SSH | 실행 구조/운영 문서 제공 | 실제 별도 미니PC·SSH 서버 접속은 미검증 |
| Chrome 선택 수집기 | manifest/클릭 대상 보존 테스트 | 실제 확장 설치·페이지 이동 수집은 수동 검증 필요 |
| 웹 스토어·네이티브 exe | 미수행 | 후속 단계 |

## 자동화 검증 범위

- 양성/음성 HTML fixture의 CSP, frame 보호, nosniff, HSTS, 쿠키 속성, mixed resource 관찰.
- 403/500/redirect/잘린 응답/압축·비HTML 응답을 정상 또는 조치 완료로 취급하지 않는지 검증.
- origin/path/userinfo/query/예약 주소·포트 제한, 모든 DNS 답변 검증, 소켓 고정, 실행 도중 DNS 집합 변경 거부.
- redirect 미추적, 응답 byte cap, 전체 deadline, DNS 대기·수신 중 취소.
- Host/Origin/세션 토큰 및 정규화 전후 경로를 사용한 교차 사이트 요청 차단.
- 프로젝트 → 실행 → 증적 → 판단 → 재검사 → HTML/JSON 보고서 → 삭제 API 흐름.
- fixed 항목 재발 시 재개방, pass 시 not_observed이며 fixed 자동 확정은 안 함, HTTP 실패 시 inconclusive.
- AI 최소 입력과 순차 batch, 알려진 ID, JSON schema/크기, cloud/remote 모델 거부, timeout·중단, AI와 판단 상태 분리.
- DB 재시작 interrupted 상태, Mac의 DB/WAL/SHM 권한 0600, 감사 이벤트 변조 검출.
- 일반 문구의 Basic 오마스킹 회귀, 구조화 secret·쿠키·쿼리 마스킹.

`npm run test:browser`는 프로젝트 생성·경로 승인·실행·근거 표시·판단 저장·감사 표시·HTML 다운로드·390px 반응형 배치·JavaScript 예외 없음까지 확인했다. 스크린샷은 `artifacts/browser/`에 생성되고 Git에서는 제외한다. README의 화면은 이 합성 fixture에서 나온 실제 화면이다.

## 실제 모델 연동에서 찾고 수정한 문제

테스트용 Ollama를 `127.0.0.1:11435`에 `OLLAMA_NO_CLOUD=1`로 실행했고 로그에서 `Ollama cloud disabled: true`를 확인했다. 모델 다운로드와 실제 진단 데이터 전송은 없었다.

- 모델: `deepseek-r1:14b`
- tags의 모델 digest: `c333b7232bdb521236694ffbb5f5a6b11cc45d98e9142c73123b670fca400b09`
- 최종 prompt version: `pentri-local-advisory-v2`
- 최종 한국어 합성 관찰 1건: 약 **75.8초**, 1개 의견 반환, ID/스키마 검증 통과.

초기 요청은 JSON Schema의 긴 문자열 반복 제한이 Ollama/llama.cpp grammar 복잡도 제한을 넘어 HTTP 400으로 실패했다. decoding schema의 문자열 길이 제약을 단순화하고 **앱 출력 검증의 2,000자 상한은 유지**했다. thinking 지원 모델은 `think:false`를 보내고 짧은 한국어 의견 요청을 명시했다. 별도 초기 출력 1건은 앱 스키마 검증에서 거부되었다. 이 실패를 성공으로 보관하지 않았다.

실제 출력의 영문 `basic CSP`가 인증 문자열로 오마스킹되는 문제도 발견해 Basic 토큰은 디코딩 결과에 `:`가 있는 경우만 처리하도록 수정하고 테스트를 추가했다. 구조화 Authorization 헤더 자체는 계속 전체 마스킹한다.

최종 응답에도 일부 중국어가 섞인 문구가 있었다. 응답 언어 안정성·조치안 정확도·모델별 오탐 감소 효과·여러 관찰의 장시간 성능은 검증되지 않았다. 단일 smoke test는 모델 추천이나 진단 정확도 평가가 아니다. 호출별 120초 상한을 초과하는 환경에서는 실패 사유를 보관하고 더 작은 모델/짧은 입력을 검토한다.

## 아직 완료되지 않은 제품 범위

현재 규칙은 HTTP 구성 관찰 6종이며 전체 웹 취약점 자동 진단을 달성하지 않았다. 인증 세션, crawler/실제 JS 실행, SQLi/XSS/접근제어 능동 검증, 업무로직 진단, CVE 오프라인 DB, 기존 Cipher·CheatSheet·문구함 이관, 스크린샷 증적 편집, 조직 보고서 템플릿, 스케줄·이행 담당자 관리, DB 암호화·보존 만료, 네이티브 설치/서명은 후속 단계다.

개발 방향은 `implementation-plan.md`에 유지한다. 다음 M2는 실제 사용자 대상 시나리오와 검증 corpus를 먼저 확정한 뒤 인증/정밀 수집·규칙 coverage를 확대하는 단계다. 기능 개수보다 재현 가능한 근거, scope 위반 방지, 실패 기록, 오탐/미탐 측정을 기준으로 진행한다.

## 휴대용 패키징 검증

로컬 Homebrew Node는 libnode 및 Homebrew 라이브러리에 동적 연결되어 그대로 휴대할 수 없음을 확인했다. 패키징은 이 빌드를 거부하도록 보강했다. 공식 Node 24.14.0 darwin-arm64 아카이브를 작업 폴더에 받아 SHASUMS256과 대조했다(SHA256 `a1a54f46a750d2523d628d924aab61758a51c9dad3e0238beb14141be9615dd3`). 공식 런타임과 LICENSE를 포함한 휴대용 폴더를 생성했다. 모델 가중치와 진단 DB는 포함하지 않았다.

생성된 Mac 휴대 폴더의 `runtime/node`(공식 Node 24.14.0)만 사용해 구문 검사와 46개 회귀 테스트를 다시 실행했고 모두 통과했다. 소스 실행 환경의 Homebrew Node 24.14.1과 구분한 검증이다.
