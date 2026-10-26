# Research and positioning

Source selection was recorded for the batch on 2026-10-26. These links are primary documentation/repository sources. This project does not contain third-party implementation code or downloaded wheel samples.

## Documented facts

- The [PyPA binary distribution format specification](https://packaging.python.org/en/latest/specifications/binary-distribution-format/) defines wheel ZIP contents, `.dist-info`, WHEEL headers, RECORD hashes, and spreading `.data/{scheme}` into installation destinations. It also describes generated console/GUI entry-point wrappers. This motivates checking archive contents before comparing logical destinations and treating unsupported transformations as unverified.
- The [OpenCV Python project's package selection guidance](https://github.com/opencv/opencv-python#installation-and-usage) warns that its package alternatives share the `cv2` namespace and users should select only one. This is an explicit real-world motivation for file ownership overlap; no current OpenCV release was downloaded or independently reproduced here.
- The [pip check command documentation](https://pip.pypa.io/en/stable/cli/pip_check/) describes verifying installed packages' compatible dependencies. It does not describe a pre-install comparison of two local wheel payload footprints.

## Design inference

A small offline comparator could help a developer or CI job distinguish different distribution names from distinct installed paths, without executing packages. Exact files and file-as-directory prefixes are an actionable bounded contract; shared namespace directories alone are not evidence of a collision. Merged versus split purelib/platlib and path case behavior must be explicit because environments differ.

Those are design judgments. This implementation checks a strict subset, not every legal wheel, every installer transform, or an existing environment. It makes unsupported spreading and wrapper creation visible instead of declaring full-install cleanliness.

## Alternatives and unknowns

Use pip to install/resolve dependencies and `pip check` for installed dependency consistency. Use an isolated environment and real import/integration tests for runtime and native-library behavior. General ZIP listing/hash tools can inspect individual archives; this project's narrower contribution is validated cross-wheel destination comparison plus explicit unsupported states. It is not a replacement for those tools.

No user interviews, download statistics, installations in a real environment, adoption, Stars, revenue, or comprehensive competitor census have been established. Demand and usefulness beyond the synthetic acceptance cases remain hypotheses. The tool does not authenticate RECORD signatures, detect malicious code, validate target compatibility, or certify supply-chain security.
