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

## GitHub REST API description license

    MIT License
    
    Copyright (c) 2020 GitHub
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
