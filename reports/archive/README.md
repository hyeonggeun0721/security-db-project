# reports/archive — 초기 스냅샷 / 스크래치 출력

이 폴더의 파일들은 **프로젝트 초기 단계의 스냅샷·스크래치 출력**이다.
지금의 스키마·마이그레이션 상태와 **안 맞을 수 있으니 참고용으로만** 본다.

| 파일 | 원래 위치 | 무엇 | 낡은 이유 |
|---|---|---|---|
| `roles_list.txt` | 루트 | 초기 `\du` 롤 목록 + `resource_limits.sql` 기준 연결제한/세션 파라미터 psql 출력 | 정적 덤프라 이후 변경(V016/V029/V037 등)이 반영 안 됨 |
| `example_query_results.txt` | 루트 | `security_db_starter.sql` 하단 예제 쿼리 (1)~(4) 실행 결과 검증 | **"전체 17개 SQL 파일 적용" 시점**(V017 시절) 기준 — 현재는 V037 까지 있음 |

**최신 상태는 여기서 본다:**

- [`../PROJECT_LOG.md`](../PROJECT_LOG.md) — 「현재 상태」 섹션 (라이브 DB 값, 적용 마이그레이션, launchd 스케줄)
- [`../../sql/schema_dump.sql`](../../sql/schema_dump.sql) — 현재 스키마 전체 덤프
- [`../../sql/RUN_ORDER.md`](../../sql/RUN_ORDER.md) — 마이그레이션 순서·의존관계의 정본
