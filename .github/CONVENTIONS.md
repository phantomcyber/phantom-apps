# Conventions in use by Phantom GitHub Repository

## Code and Style
The Phantom Apps team utilizes Python for its Apps. Consequently, we have standardized on [PEP8](https://www.python.org/dev/peps/pep-0008/) style. Additionally, in our automated testing we the [Flake8](http://flake8.pycqa.org/en/latest/) linter.

We would ask that you follow these guidelines when developing your App to ensure consistency without our platform.

## App Naming Convetion
Our App directories follow the pattern of `ph`+`app-name`. For example, AWS IAM has the name "awsiam" and we prepend "ph" on the front, leaving us with `phawsiam` (always in lower case).  If you were going to create a new App for "Awesome API" then you would create a folder under `Apps` called `phawesomeapi`. Please feel free to look around in that directory to acquaint yourself with this pattern.

