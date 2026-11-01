//! Bounded S25 semantic palette and accessibility projection. This is
//! computed presentation data, never proof of actual native rendered state.
//! No arbitrary QML/JS/CSS, imported executable themes or external URLs.

use linura_transaction::{
    AccentPreset, Density, FontPreset, IconPreset, PersonalizationChoices, ThemeMode,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rgb {
    pub red: u8,
    pub green: u8,
    pub blue: u8,
}

impl Rgb {
    pub const fn new(red: u8, green: u8, blue: u8) -> Self {
        Self { red, green, blue }
    }

    fn luminance(self) -> f64 {
        fn component(value: u8) -> f64 {
            let n = f64::from(value) / 255.0;
            if n <= 0.04045 { n / 12.92 } else { ((n + 0.055) / 1.055).powf(2.4) }
        }
        0.2126 * component(self.red)
            + 0.7152 * component(self.green)
            + 0.0722 * component(self.blue)
    }

    #[must_use]
    pub fn contrast_ratio(self, other: Self) -> f64 {
        let a = self.luminance().max(other.luminance());
        let b = self.luminance().min(other.luminance());
        (a + 0.05) / (b + 0.05)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectiveScheme {
    Light,
    Dark,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticColors {
    pub background: Rgb,
    pub surface: Rgb,
    pub foreground: Rgb,
    pub accent: Rgb,
    pub on_accent: Rgb,
    pub muted: Rgb,
    pub danger: Rgb,
    pub warning: Rgb,
    pub success: Rgb,
    pub focus: Rgb,
}

impl SemanticColors {
    pub const fn light() -> Self {
        Self {
            background: Rgb::new(248, 250, 252),
            surface: Rgb::new(255, 255, 255),
            foreground: Rgb::new(20, 34, 57),
            accent: Rgb::new(36, 51, 165),
            on_accent: Rgb::new(255, 255, 255),
            muted: Rgb::new(72, 84, 102),
            danger: Rgb::new(185, 28, 28),
            warning: Rgb::new(146, 64, 14),
            success: Rgb::new(22, 101, 52),
            focus: Rgb::new(36, 51, 165),
        }
    }

    pub const fn dark() -> Self {
        Self {
            background: Rgb::new(11, 18, 32),
            surface: Rgb::new(23, 34, 56),
            foreground: Rgb::new(248, 250, 252),
            accent: Rgb::new(136, 154, 255),
            on_accent: Rgb::new(16, 23, 54),
            muted: Rgb::new(200, 207, 220),
            danger: Rgb::new(255, 180, 180),
            warning: Rgb::new(255, 216, 158),
            success: Rgb::new(159, 225, 176),
            focus: Rgb::new(136, 154, 255),
        }
    }

    #[must_use]
    pub fn passes_base_contrast(&self) -> bool {
        self.foreground.contrast_ratio(self.background) >= 4.5
            && self.foreground.contrast_ratio(self.surface) >= 4.5
            && self.muted.contrast_ratio(self.surface) >= 4.5
            && self.accent.contrast_ratio(self.surface) >= 4.5
            && self.on_accent.contrast_ratio(self.accent) >= 4.5
            && self.danger.contrast_ratio(self.surface) >= 4.5
            && self.warning.contrast_ratio(self.surface) >= 4.5
            && self.success.contrast_ratio(self.surface) >= 4.5
            && self.focus.contrast_ratio(self.surface) >= 3.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalizationTokenProjection {
    pub scheme: EffectiveScheme,
    pub colors: SemanticColors,
    pub system_palette_fallback: bool,
    pub density_percent: u16,
    pub transition_milliseconds: u16,
    pub font_family: &'static str,
    pub icon_family: &'static str,
}

impl PersonalizationTokenProjection {
    /// Missing trusted system palette must be a disclosed fallback, not a
    /// claim of native Qt/compositor application. Safe roles are fixed.
    #[must_use]
    pub fn compute(choices: &PersonalizationChoices, system_dark: Option<bool>) -> Self {
        let (scheme, fallback) = match choices.mode {
            ThemeMode::Dark => (EffectiveScheme::Dark, false),
            ThemeMode::Light => (EffectiveScheme::Light, false),
            ThemeMode::System => match system_dark {
                Some(true) => (EffectiveScheme::Dark, false),
                Some(false) => (EffectiveScheme::Light, false),
                None => (EffectiveScheme::Light, true),
            },
        };
        let colors = match scheme {
            EffectiveScheme::Light => SemanticColors::light(),
            EffectiveScheme::Dark => SemanticColors::dark(),
        };
        // Trusted enum; even "system" cannot accept an arbitrary unchecked
        // color that might disguise danger, success or focus.
        let _accent = match choices.accent {
            AccentPreset::System | AccentPreset::LinuraBlue => colors.accent,
        };
        let density_percent = match choices.density {
            Density::Standard => 100,
            Density::Spacious => 120,
        };
        let font_family = match choices.font {
            FontPreset::System => "system",
            FontPreset::DejaVuSans => "DejaVu Sans",
        };
        let icon_family = match choices.icons {
            IconPreset::Linura => "linura",
        };
        Self {
            scheme,
            colors,
            system_palette_fallback: fallback,
            density_percent,
            transition_milliseconds: if choices.reduced_motion { 0 } else { 160 },
            font_family,
            icon_family,
        }
    }

    #[must_use]
    pub fn is_accessible_baseline(&self) -> bool {
        self.colors.passes_base_contrast()
            && (100..=120).contains(&self.density_percent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_roles_preserve_contrast_and_negative_status() {
        for colors in [SemanticColors::light(), SemanticColors::dark()] {
            assert!(colors.passes_base_contrast());
            assert_ne!(colors.danger, colors.success);
            assert_ne!(colors.warning, colors.success);
            assert_ne!(colors.focus, colors.background);
        }
    }

    #[test]
    fn system_fallback_is_explicit_and_does_not_claim_rendered_state() {
        let choices = PersonalizationChoices::default();
        let unknown = PersonalizationTokenProjection::compute(&choices, None);
        assert_eq!(unknown.scheme, EffectiveScheme::Light);
        assert!(unknown.system_palette_fallback);
        let dark = PersonalizationTokenProjection::compute(&choices, Some(true));
        assert_eq!(dark.scheme, EffectiveScheme::Dark);
        assert!(!dark.system_palette_fallback);
        assert!(dark.is_accessible_baseline());
    }

    #[test]
    fn motion_and_density_cannot_escape_allowlist() {
        let mut choices = PersonalizationChoices::default();
        choices.reduced_motion = true;
        choices.density = Density::Spacious;
        choices.mode = ThemeMode::Dark;
        let projection = PersonalizationTokenProjection::compute(&choices, None);
        assert_eq!(projection.transition_milliseconds, 0);
        assert_eq!(projection.density_percent, 120);
        assert!(projection.is_accessible_baseline());
    }
}
