###
### JSEC Test Runner (janet-assay version)
###
### Run tests for the jsec library using the janet-assay testing framework.
###
### Usage:
###   janet test/runner.janet [OPTIONS]
###
### See `janet test/runner.janet --help` for full option list.
###

(import assay)

# Use def-runner macro from janet-assay
# When using explicit category paths (struct format), paths are prefixed with
# base-dir (runner location) NOT suites-dir. So we use full relative paths.
(assay/def-runner
  :name "JSEC Test Runner"
  :env-prefix "JSEC"
  :categories {:unit "../suites/unit"
               :coverage "../suites/coverage"
               :regression "../suites/regression"
               :integration "../suites/integration"
               :performance "../suites/performance"})
