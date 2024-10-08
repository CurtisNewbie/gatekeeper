# gatekeeper

Simple custom-made gateway written in Go. This project is internally backed by [curtisnewbie/miso](https://github.com/curtisnewbie/miso).

> **_This project is part of the monorepo ([https://github.com/CurtisNewbie/moon-monorepo](https://github.com/CurtisNewbie/moon-monorepo)). This repo is nolonger maintained, latest changes are commited to the monorepo instead._**

## Dependencies

- Consul
- [github.com/curtisnewbie/user-vault](https://github.com/curtisnewbie/user-vault)

## Configuration

See [miso](https://github.com/curtisnewbie/miso) for more about configuration.

| Property                           | Description                                                                 | Default Value |
| ---------------------------------- | --------------------------------------------------------------------------- | ------------- |
| gatekeeper.timer.path.excl         | slice of paths that are not measured by prometheus timer                    |               |
| gatekeeper.whitelist.path.patterns | slice of path patterns that do not require authorization and authentication |               |

