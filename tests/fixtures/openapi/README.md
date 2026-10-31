# Public OpenAPI specs for the REST uploads tests

- `github-excerpt.json`: seven operations from GitHub's REST API
  description (`descriptions/api.github.com/api.github.com.json` in
  https://github.com/github/rest-api-description, MIT License, Copyright (c)
  2020 GitHub), as fetched on 2026-10-31. Kept: the operations' request
  bodies and parameters and every component they reference; each response is
  trimmed to a one-line stub, since RailDash reads only request bodies.
- `petstore3.json`: the Swagger Petstore OpenAPI 3.0 spec as served at
  https://petstore3.swagger.io/api/v3/openapi.json on 2026-10-31 (Apache
  License 2.0), unchanged: its `uploadImage` takes `application/octet-stream`.
