# Changelog

## [0.2.0] - 2020-04-11
### Added
- Ability for websockets to kill running process.
- New endpoint `run/background` for running long commands in the background.

## [0.1.6] - 2019-05-13
### Added
- Realtime websockets to stream CLI output to CaptainCore GUI.
- Relay websockets when command is deferred to another CaptainCore CLI.

## [0.1.5] - 2019-04-22
### Added
- Relay site commands to servers. Commands are changed to bare version. Example `site add` is sent to remote servers as `site bare-add`.

## [0.1.4] - 2019-03-18
### Added
- Fleet Mode  ⛵⛵⛵ (support for multiple captains). Tokens are now assigned to a CaptainID which grants access to just their sites. See `config.json.sample` for new token format.
- Support for multiple CaptainCore servers. Can specify server within config.json and list out commands which will be sent direct to that server rather then run locally.
- A deferred command will track the origin server info. This is used to mark the origin server Job completed once the command has completed. 

## [0.1.3] - 2019-03-03
### Changed
- Bug fix when passing arguments with double quotes to command line

## [0.1.2] - 2019-02-07
### Added
- New argument`--debug` to `server` command
- Favicon

## [0.1.1] - 2018-12-31
### Added
- New endpoint `/run` for running and outputting response immediately.
- After a task has finished running store any JSON results within `task.response`.
- Pagination for `/tasks/<page>`
- Parse command line arguments using regular expressions.

## [0.1.0] - 2018-12-22
### Added
- Initial release: Golang web server built using [Mux](https://github.com/gorilla/mux), [Cobra](https://github.com/spf13/cobra), [Gorm](http://gorm.io/), [Sqlite](https://www.sqlite.org), self signed CA/Cert (Local HTTPS) and Let's Encrypt support (Production HTTPS).