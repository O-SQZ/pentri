# PenTri

Chrome extension for collecting and organizing information during manual web security assessments.

[Install from the Chrome Web Store](https://chromewebstore.google.com/detail/pentri/johfegfkdkpbckcekhmkkmhilpmlaeem)

## Features

- Inspect the active tab's technology stack and HTTP security headers
- Collect forms, input fields, hidden fields, upload fields, and cookie attributes
- Find JavaScript files, security-related patterns, hardcoded key candidates, and XSS filtering code
- Check source map candidates, `robots.txt`, `sitemap.xml`, and sensitive paths
- Analyze external JavaScript comments and security patterns without executing the files
- Encode and decode values, generate hashes, and inspect JWT structures
- Manage assessment payloads and reusable notes
- Export collected results and notes as JSON or HTML

## Safe Use

- PenTri inspects only the active tab after an explicit user action.
- It does not send requests without user initiation or automatically determine vulnerabilities.
- It does not provide automatic exploitation or authentication bypass features.
- Use it only on websites and applications you are authorized to assess.
- Page contents, cookies, tokens, and scan results are not sent to the developer's server.
- An optional CVE lookup may send a selected technology keyword to the public NVD API.

See the [Privacy Policy](privacy/개인정보처리방침.md) for details.

## Current Status

- Public version: **v1.10** (`manifest.version`: `1.1.0`)
- Distribution: Chrome Web Store (v1.10 update under review)
- Source code: Public in this repository

## Local Installation

1. Clone this repository or extract the v1.10 release ZIP.
2. Open `chrome://extensions` in Chrome.
3. Enable **Developer mode**.
4. Select **Load unpacked** and choose the source directory.

## Repository Structure

```text
assets/     Icons, styles, detection signatures, and assessment data
background/ Manifest V3 service worker
content/    Active-tab collection and static analysis
devtools/   DevTools entry point
popup/      User interface and result handling
docs/       GitHub Pages and privacy policy
privacy/    Privacy policy source
manifest.json
```

---

<details>
<summary><strong>한국어 안내</strong></summary>

웹 보안 수동 진단 과정에서 필요한 정보를 수집하고 정리하는 Chrome 확장 프로그램입니다.

[Chrome Web Store에서 설치하기](https://chromewebstore.google.com/detail/pentri/johfegfkdkpbckcekhmkkmhilpmlaeem)

### 주요 기능

- 활성 탭의 기술 스택과 HTTP 보안 헤더 확인
- 폼, 입력 필드, hidden field, 업로드 필드 및 쿠키 속성 수집
- JavaScript 파일, 보안 패턴, 하드코딩된 키 후보 및 XSS 필터링 코드 탐색
- source map 후보, `robots.txt`, `sitemap.xml` 및 민감 경로 확인 보조
- 외부 JavaScript 파일을 실행하지 않고 주석과 보안 패턴 정적 분석
- 인코딩·디코딩, 해시 생성 및 JWT 구조 확인
- 진단용 Payload와 반복 사용 문구 관리
- 수집 결과와 메모를 JSON·HTML로 내보내기

### 안전한 사용 원칙

- 사용자가 명시적으로 실행한 활성 탭만 점검합니다.
- 사용자의 실행 없이 요청을 보내거나 자동으로 취약점을 확정하지 않습니다.
- 자동 익스플로잇이나 인증 우회 기능을 제공하지 않습니다.
- 허가받은 웹사이트와 애플리케이션에서만 사용해야 합니다.
- 페이지 본문, 쿠키, 토큰과 스캔 결과를 개발자 서버로 전송하지 않습니다.
- 선택적 CVE 조회 시 기술 키워드가 NVD 공개 API로 전달될 수 있습니다.

자세한 내용은 [개인정보처리방침](privacy/개인정보처리방침.md)에서 확인할 수 있습니다.

### 현재 상태

- 공개 버전: **v1.10** (`manifest.version`: `1.1.0`)
- 배포: Chrome Web Store (v1.10 업데이트 심사 중)
- 소스코드: 이 저장소에서 공개

### 로컬 설치

1. 저장소를 내려받거나 v1.10 릴리스 ZIP을 압축 해제합니다.
2. Chrome에서 `chrome://extensions`를 엽니다.
3. **개발자 모드**를 켭니다.
4. **압축해제된 확장 프로그램을 로드합니다**를 선택하고 소스 디렉터리를 지정합니다.

### 저장소 구성

```text
assets/     아이콘, 스타일, 탐지 시그니처 및 진단 데이터
background/ Manifest V3 service worker
content/    활성 탭 정보 수집 및 정적 분석
devtools/   DevTools 진입점
popup/      사용자 인터페이스와 결과 처리
docs/       GitHub Pages 및 개인정보처리방침
privacy/    개인정보처리방침 원문
manifest.json
```

</details>
