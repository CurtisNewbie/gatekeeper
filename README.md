# gatekeeper

Simple custom-made gateway written in Go. This project is internally backed by [curtisnewbie/miso](https://github.com/curtisnewbie/miso).

## Dependencies

- Consul
- [github.com/curtisnewbie/user-vault](https://github.com/curtisnewbie/user-vault)

## Configuration

See [miso](https://github.com/curtisnewbie/miso) for more about configuration.

| Property                           | Description                                                                 | Default Value |
| ---------------------------------- | --------------------------------------------------------------------------- | ------------- |
| gatekeeper.timer.path.excl         | slice of paths that are not measured by prometheus timer                    |               |
| gatekeeper.whitelist.path.patterns | slice of path patterns that do not require authorization and authentication |               |

