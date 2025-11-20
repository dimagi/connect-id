# Release Toggles in PersonalID

PersonalID uses [django waffle](https://waffle.readthedocs.io/en/stable/) to manage feature release toggles.

## Expectations

- PersonalID exclusively uses switches over other models in waffle, to allow global release of features without any additional targeting.
- All switches should have a detailed description in the note field of the model, describing the feature they control.

## Configuration Details

- PersonalID uses the django admin to manage the backend models and enable or disable switches.
- PersonalID uses the `WAFFLE_CREATE_MISSING_SWITCHES` so that switches are automatically added to the database when they are encountered in the codebase. However, manually adding them prior to deploy is preferred.
