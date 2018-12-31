# Changelog

## [0.1.1] - 2018-12-31
### Added
- New endpoint `/run` for running and outputting response immediately.
- After a task has finished running store any JSON results within `task.response`.
- Pagination for `/tasks/<page>`
- Parse command line arguments using regular expressions.

## [0.1.0] - 2018-12-22
### Added
- Initial release: Golang web server built using [Mux](https://github.com/gorilla/mux), [Cobra](https://github.com/spf13/cobra), [Gorm](http://gorm.io/), [Sqlite](https://www.sqlite.org), self signed CA/Cert (Local HTTPS) and Let's Encrypt support (Production HTTPS).