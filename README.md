# PenTri

PenTri는 승인된 웹 애플리케이션 보안 진단에서 반복되는 초기 정보 수집과 결과 정리를 보조하는 Chrome 확장 프로그램입니다.

자동으로 취약점을 확정하거나 공격을 수행하는 도구가 아닙니다. 사용자가 현재 활성 탭에서 직접 실행하며, 수집 결과를 검토해 실제 취약 여부와 영향을 판단하는 흐름을 전제로 설계했습니다.

[Chrome Web Store에서 PenTri 설치하기](https://chromewebstore.google.com/detail/pentri/johfegfkdkpbckcekhmkkmhilpmlaeem)

## 주요 기능

- 활성 탭의 기술 스택과 HTTP 보안 헤더 확인
- 폼, 입력 필드, hidden field 및 업로드 필드 수집
- 쿠키와 보안 속성 확인
- JavaScript 파일과 보안 관련 패턴 탐색
- source map 후보 및 접근 가능 여부 확인 보조
- robots.txt·sitemap.xml 및 민감 경로 확인 보조
- 외부 JavaScript 주석·보안 패턴 정적 분석
- 이중 인코딩·디코딩 도구
- 해시 생성과 JWT 구조 확인
- 진단용 Payload·문구 관리
- 하드코딩된 키 후보와 XSS 필터링 코드 탐색 보조
- 수집 결과 및 메모의 JSON·HTML 내보내기

## 실제 활용 범위

PenTri는 웹 진단 과정에서 다음과 같은 반복 작업을 빠르게 확인하기 위해 사용하고 있습니다.

- 여러 단계의 인코딩 값을 한 화면에서 변환·비교
- 일반적인 문자열 검색에서 놓치기 쉬운 JavaScript 내 키 후보 탐색
- XSS 필터링 로직과 클라이언트 측 검증 코드 확인
- JavaScript 참조를 바탕으로 source map 후보와 공개 여부 점검

수집 결과는 취약점 판정이 아닌 **검토 후보**입니다. 서비스 구조, 권한 조건, 재현 가능성과 실제 영향을 진단자가 별도로 확인해야 합니다.

## 안전한 사용 원칙

- 사용자가 명시적으로 실행한 활성 탭만 점검합니다.
- 사용자의 실행 없이 요청을 보내거나 자동으로 취약점을 확정하지 않습니다.
- 자동 익스플로잇이나 인증 우회 기능을 제공하지 않습니다.
- 허가받은 웹사이트와 애플리케이션에서만 사용해야 합니다.
- 페이지 본문, 쿠키, 토큰과 스캔 결과를 개발자 서버로 전송하지 않습니다.
- 선택적 CVE 조회 시 기술 키워드가 NVD 공개 API로 전달될 수 있습니다.

자세한 데이터 처리 범위는 [개인정보처리방침](privacy/개인정보처리방침.md)에서 확인할 수 있습니다.

## 현재 상태

- 공개 버전: **v1.10** (`manifest.version`: `1.1.0`)
- 배포: Chrome Web Store
- 소스코드: 이 저장소에서 공개

## 로컬 설치

1. 저장소를 내려받거나 v1.10 릴리스 ZIP을 압축 해제합니다.
2. Chrome에서 `chrome://extensions`를 엽니다.
3. **개발자 모드**를 켭니다.
4. **압축해제된 확장 프로그램을 로드합니다**를 선택하고 소스 디렉터리를 지정합니다.

## 저장소 구성

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

## 문의

- GitHub: [O-SQZ](https://github.com/O-SQZ)
- 이메일: max5131004@gmail.com
