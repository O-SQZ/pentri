# 실행·휴대·내부망 운영

## Windows와 Mac

소스 실행에는 Node 24.14 이상 24.x가 필요하다. `npm start`는 서버만, `npm run desktop` 또는 루트의 Start-PenTri 런처는 서버와 기본 브라우저를 연다. UI는 같은 브라우저의 별도 탭이며 확장이 필요 없다. 브라우저 창을 닫아도 서버는 유지된다. 종료는 터미널의 Ctrl+C다.

`npm run package:portable`은 현재 OS/아키텍처의 Node 실행 파일, Node 라이선스, 앱 소스와 문서, SHA256SUMS를 `dist/`에 모은다. 인터넷 다운로드를 하지 않는다. 공식 Node 바이너리 배포판을 사용해야 한다. Homebrew처럼 외부 libnode 등에 연결된 빌드는 거부한다. 공식 아카이브를 압축 해제하고 `PENTRI_NODE_DIR=/path/to/node-v24.14.0-darwin-arm64 npm run package:portable`로 지정한다. Windows PowerShell에서는 `$env:PENTRI_NODE_DIR='C:\path\node-v24.14.0-win-x64'; npm run package:portable`을 사용한다. 공식 아카이브와 SHASUMS는 [Node 배포 서버](https://nodejs.org/dist/v24.14.0/)에서 확인한다.

배포 폴더를 압축해 같은 OS/아키텍처의 쓰기 가능한 사용자 폴더에 풀고 런처로 실행할 수 있다. Mac arm64 결과를 Windows에 복사해서 실행할 수는 없다. Windows 빌드는 Windows CI 산출물을 사용한다. Ollama와 모델 가중치는 포함하지 않는다. 네이티브 창·서명된 설치 프로그램·자동 업데이트는 후속 단계다.

## 환경 변수

GitHub Actions의 Artifacts에서 OS별 배포물을 받을 수 있다. Windows는 내부 ZIP, Mac/Linux는 내부 tar.gz를 풀어 사용한다. Mac/Linux 실행 권한은 tar.gz 내부에 보존한다. CI 산출물 보존 기간은 14일이며 정식 릴리스 설치 파일과 구별한다.

| 변수 | 기본값 | 의미 |
| --- | --- | --- |
| PENTRI_PORT | 8787 | UI/API loopback 포트 |
| PENTRI_DATA_DIR | .pentri | 진단 DB 디렉터리 |
| PENTRI_OLLAMA_URL | http://127.0.0.1:11434 | loopback Ollama 주소. DNS 호스트명과 원격 주소는 거부 |
| DEMO_PORT | 9080 | 데모 대상 포트 |
| DEMO_FIXED | unset | 1이면 데모의 개선된 설정 |

환경 변수는 프로세스 실행 환경에서 설정한다. `.env` 파일을 자동으로 읽지 않는다. PowerShell 예: `$env:PENTRI_PORT='8788'; npm start`. macOS/Linux 예: `PENTRI_PORT=8788 npm start`.

## 휴대 미니PC

미니PC에 앱·Node·Ollama·모델을 준비하고 앱과 Ollama를 같은 미니PC에서 실행한다. UI/API와 Ollama는 각각 loopback에만 노출한다. 진단 요청은 **미니PC의 네트워크 위치와 DNS**를 사용한다.

노트북에서 SSH로 연결한다(SSH 서버와 계정/키는 운영자가 사전 구성).

```sh
ssh -N -L 127.0.0.1:8787:127.0.0.1:8787 user@mini-pc
```

노트북 브라우저에서 `http://127.0.0.1:8787`을 연다. Host 검증 때문에 양 끝 앱 포트를 동일하게 맞춘다. 이미 노트북에서 8787을 사용 중이면 기존 앱을 종료하거나 미니PC의 PENTRI_PORT와 터널의 양 끝 포트를 함께 바꾼다. Ollama 포트는 노트북으로 노출할 필요 없다. SSH 종료 후 UI 접근은 끊기지만 미니PC의 실행은 계속될 수 있다. 중단하려면 먼저 UI에서 진단/AI 중단을 요청한다.

이 버전은 단일 사용자 운용을 전제로 한다. 직접 `0.0.0.0` 바인딩, 인증 없는 LAN 대시보드, 다중 사용자 계정 관리는 제공하지 않는다. 공유 서비스화에는 TLS, 사용자 인증, 역할별 권한, 작업 격리가 추가로 필요하다.

## 오프라인 반입과 모델 선택

앱·Node 런타임·Ollama 설치 파일·선택 모델을 반입 전에 준비하고 각각의 라이선스/해시를 기록한다. 앱에는 모델 다운로드/자동 업데이트/외부 CVE 조회 기능이 없다. Ollama는 `OLLAMA_NO_CLOUD=1`로 시작하고 로그의 cloud 비활성화 여부를 확인한다. 폐쇄망 정책은 OS/네트워크 방화벽에서도 적용한다. 로컬 API 주소만으로 서버 내부의 외부 통신 여부까지 증명하지 못한다.

모델 크기는 실제 RAM/VRAM과 동시 실행 프로그램을 기준으로 결정한다. 2026-09-15 실기 검증 장비는 Apple M2/16 GiB, 설치 모델은 deepseek-r1:14b였다. 이 조합의 결과는 validation.md에 기록하며 모든 환경에 대한 권장 모델로 일반화하지 않는다. 메타데이터에 GGUF/completion이 없거나 cloud/remote로 표시된 모델은 거부한다. 작은 모델부터 고정 fixture의 구조화 응답 성공률과 속도를 측정하는 절차를 권장한다.

## 보존·삭제·복구

자동 보존 만료는 아직 없다. 프로젝트를 삭제할 때까지 증적·검토·AI 의견·감사 로그가 DB에 남는다. UI의 프로젝트 삭제는 해당 자료를 함께 제거하고 WAL checkpoint를 수행한다. 다운로드한 보고서와 시스템 백업·파일시스템 스냅샷은 별도로 관리해야 한다. 안전한 물리적 소거를 보장하지 않는다.

DB는 암호화되어 있지 않다. Mac/Linux의 신규 디렉터리와 DB/sidecar는 0700/0600 권한을 사용한다. Windows는 사용자 전용 디렉터리의 ACL을 사용하고 운영자가 검증한다. FileVault/BitLocker 등 디스크 보호를 운영 환경에 맞게 적용한다.

백업은 앱을 정상 종료한 뒤 데이터 디렉터리를 복사한다. 복원은 같은 버전으로 검증한다. 비정상 종료 중인 작업은 다음 시작 시 `interrupted`로 표시되고 자동 재개되지 않는다. 같은 DB를 여러 앱 프로세스에서 동시에 사용하는 방식은 지원하지 않는다.

## 선택 Chrome 수집기

`chrome://extensions`에서 개발자 모드 → 압축해제된 확장 로드 → 저장소의 `extension/`을 선택한다. 대상 페이지에서 아이콘을 누르면 별도 수집 탭이 열린다. URL 확인 → 관찰 수집 → JSON 저장 → 독립 앱 Tools에서 가져오기를 수행한다.

수집은 명시적으로 선택한 탭의 DOM 제목·URL·정적 링크/리소스·주석·폼 메타데이터에 한정한다. 입력 값·쿠키·저장소를 읽지 않는다. 서버 측 판단이나 증적 캡처 이미지는 제공하지 않는다. 페이지 이동 시 다시 대상에서 아이콘을 클릭한다. 가져오기는 프로젝트의 origin과 허용 경로가 맞아야 하며 링크를 자동 요청하지 않는다. 스토어 패키지로 제출한 상태는 아니다.
