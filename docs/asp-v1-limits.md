# ASP v1 capacity limits

RailDash applies separate bounds to ASP evidence input and redacted drift
output. They are contract constants in `raildash.asp` and are exercised by the
ASP test suite.

| Surface | Bound | Measurement / rationale |
|---|---:|---|
| Exact evidence-bundle input | 1 MiB | The checked-in real redacted RailMon bundle is 5,015 bytes. A valid synthetic bundle with 1,000 high-cardinality attributes is 431,782 bytes, leaving more than 2x headroom at the input boundary. |
| Redacted drift-result detail | 256 KiB and 500 changes | The comparator stops before the compact UTF-8 result exceeds the byte bound, preserves the total `change_count`, and sets `truncated`. The byte test uses long valid attribute names so the byte bound binds before the count bound. |
| Drift-summary page | 100 default, 500 maximum | Matches the existing RailDash interaction API. The M2 summary endpoint must import these constants rather than choose another pagination contract. |

The evidence limit is intentionally smaller than the 16 MiB webhook limit.
Webhook interactions can contain escaped 1 MiB request and response bodies;
the evidence contract contains structured attributes rather than captured HTTP
bodies. JSON nesting and structure-token guards still apply before parsing.
