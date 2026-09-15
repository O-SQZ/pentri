# 출처와 라이선스 상태

새 코어와 UI는 이 저장소에서 작성했고 앱 런타임 npm 외부 의존성을 사용하지 않는다. Node 내장 HTTP/SQLite 등은 해당 Node 배포판의 라이선스를 따른다. 휴대용 패키징은 공식 Node 실행 파일과 배포판의 전체 `LICENSE`를 함께 포함한다. Ollama와 모델은 배포본에 넣지 않으며 각각의 라이선스를 별도로 검토해야 한다.

첨부 `pentri-v1.10-patched.zip` SHA256:

```text
8a5dff3f08abdc90edbea95963de5d2938842ed7f050d0ef9ff93164ed8347a0
```

첨부 코드는 정적으로 분석했으며 새 런타임에 원본 Acorn, Wappalyzer 계열 DB, 기술 아이콘, 페이로드 DB를 복사하지 않았다. 원본 출처·라이선스 미확인 항목은 [정적 분석](docs/legacy-audit.md)에 남겼다. 원본 ZIP과 실제 진단 기록은 Git에 포함하지 않는다.

프로젝트 전체 공개 라이선스와 기존 소스 권리 관계는 아직 확정되지 않았다. 임의의 오픈소스 라이선스를 부여하지 않았다. 외부 재배포·스토어 제출 단계에서 소유자가 확정해야 한다. 현재 저장소의 공개 여부 자체가 제3자 라이선스 부여를 뜻하지 않는다.

설계 참고: [Ollama API](https://docs.ollama.com/api/chat), [구조화 출력](https://docs.ollama.com/capabilities/structured-outputs), [Chrome action API](https://developer.chrome.com/docs/extensions/reference/api/action). 문서 내용은 구현 근거로 참조했고 해당 페이지나 예제를 통째로 재배포하지 않는다.
