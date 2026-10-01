-- Linura arch-hyprland-v1 compositor profile.
-- Keep the upstream Hyprland defaults, then add bounded navigation-only shell entry chords.
require("/usr/share/hypr/hyprland")

hl.bind("SUPER + CTRL + P", hl.dsp.global("linura:workstationPanel"))
hl.bind("SUPER + CTRL + S", hl.dsp.global("linura:quickSettings"))
hl.bind("SUPER + SPACE", hl.dsp.global("linura:commandPalette"))
