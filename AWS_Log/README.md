## AWS Log Parser

AWS CloudTrail, VPC Flow, S3 Server Access 로그를 통합 파싱/분석하여 CSV, Excel, HTML 리포트를 생성하는 도구입니다. Windows/macOS/Linux에서 동작하며 대용량 로그를 병렬로 처리합니다.

### 지원 로그 타입
- **CloudTrail**: JSON/JSONL/JSON.GZ
- **VPC Flow Log**: space-separated 텍스트(.log/.txt/.gz)
- **S3 Server Access Log**: 표준 S3 액세스 로그 라인(.log/.txt/.gz)

### 주요 기능
- 멀티프로세싱 기반 대용량 로그 파싱
- 로그별 CSV 저장 및 결과 디렉터리 자동 구성
- 분석 결과 Excel 생성
  - CloudTrail: 11개 시트(Top IP, 야간 이벤트, UserAgent, 실패 인증, Region, ConsoleLogin, CreateUser, MITRE 등)
  - VPC Flow: 5개 시트(Top IP Bytes, Port/Protocol, 야간 원격접속, 세션지속시간, Top 연결)
  - S3 Access: 5개 시트(요청자/출발지 IP, 버킷/프리픽스별 동작, UserAgent, MITRE 전술/이벤트)
- HTML 요약 리포트 생성(Chart.js 시각화)
- `mitre_config.json` 기반 MITRE ATT&CK 전술 매핑(CloudTrail, S3 Access)

---

### 요구 사항
- Python 3.9 이상 권장
- 의존 패키지
  - pandas, numpy
  - tqdm
  - openpyxl

설치:

```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate # macOS/Linux
pip install --upgrade pip
pip install pandas numpy tqdm openpyxl
```

---

### 실행 방법(인터랙티브 모드)
프로젝트 루트에서 아래와 같이 실행하세요.

```bash
python main.py
```

실행 흐름:
1) 출력 폴더 경로 입력(없으면 생성 선택 가능)
2) CloudTrail / VPC Flow / S3 Access 로그 폴더 경로 입력
   - 로그 타입별 입력은 선택적입니다. 없으면 `N` 입력으로 건너뛰기
3) 요약 확인 후 분석 시작(y)

분석이 완료되면 지정한 출력 폴더 아래에 결과가 생성됩니다.

---

### 출력 디렉터리 구조
`<Output>/Result` 아래에 다음 폴더와 파일이 생성됩니다.
- `Parse_Logs/`
  - `cloudtrail_log_YYYYMMDD_HHMMSS.csv`
  - `vpc_log_...csv` 또는 `vpc_flow_log_...csv` (파서 출력명에 따름)
  - `s3_log_...csv` 또는 `s3_access_log_...csv` (파서 출력명에 따름)
- `Analysis_Logs/`
  - 로그별 분석 Excel: `cloudtrail_analysis_*.xlsx`, `vpc_flow_analysis_*.xlsx`, `s3_access_analysis_*.xlsx`
- `Report/`
  - 로그별 HTML 리포트: `cloudtrail_analysis_report.html`, `vpc_flow_analysis_report.html`, `s3_access_analysis_*.html`
- `log.txt`: 콘솔 출력 이중 기록

참고: 각 파서는 내부적으로 시점에 따라 파일 접미사(타임스탬프)가 다를 수 있습니다.

---


### MITRE ATT&CK 매핑
- `mitre_config.json`에서 전술별 이벤트/오퍼레이션을 정의합니다.
  - `cloudtrail` 키: CloudTrail의 `eventName` 매핑
  - `s3_access_log` 키: S3 Access의 `operation` 매핑(예: `REST.GET.OBJECT`)
- 필요 시 전술/이벤트 목록을 추가/수정하면 보고서에 즉시 반영됩니다.

---

### HTML 리포트
- Chart.js CDN을 사용합니다. 인터넷 연결이 제한된 환경에서는 HTML 내 `<script src>`를 내부 호스트로 교체하거나 로컬 파일로 대체해 사용하세요.

---

이후 안내에 따라 출력 폴더와 각 로그 폴더를 입력하면 결과가 `<Output>/Result` 하위에 생성됩니다.


