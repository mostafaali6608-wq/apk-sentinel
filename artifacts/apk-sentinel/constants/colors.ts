/**
 * Semantic design tokens for the mobile app.
 *
 * These tokens mirror the naming conventions used in web artifacts (index.css)
 * so that multi-artifact projects share a cohesive visual identity.
 *
 * Replace the placeholder values below with values that match the project's
 * brand. If a sibling web artifact exists, read its index.css and convert the
 * HSL values to hex so both artifacts use the same palette.
 *
 * To add dark mode, add a `dark` key with the same token names.
 * The useColors() hook will automatically pick it up.
 */

const colors = {
  light: {
    text: '#E9F2FF',
    tint: '#43D9FF',
    background: '#08111F',
    foreground: '#E9F2FF',
    card: '#101D30',
    cardForeground: '#E9F2FF',
    primary: '#43D9FF',
    primaryForeground: '#06101D',
    secondary: '#182840',
    secondaryForeground: '#D7E7FA',
    muted: '#142239',
    mutedForeground: '#8CA6C4',
    accent: '#1A3147',
    accentForeground: '#BDEFFF',
    destructive: '#FF6B6B',
    destructiveForeground: '#220B12',
    border: '#203650',
    input: '#172942',
    success: '#5FE0A0',
    warning: '#FFC56B',
    high: '#FF986B',
    critical: '#FF6B8A',
    info: '#8EA8FF',
    overlay: '#0C182A',
  },
  dark: {
    text: '#E9F2FF',
    tint: '#43D9FF',
    background: '#08111F',
    foreground: '#E9F2FF',
    card: '#101D30',
    cardForeground: '#E9F2FF',
    primary: '#43D9FF',
    primaryForeground: '#06101D',
    secondary: '#182840',
    secondaryForeground: '#D7E7FA',
    muted: '#142239',
    mutedForeground: '#8CA6C4',
    accent: '#1A3147',
    accentForeground: '#BDEFFF',
    destructive: '#FF6B6B',
    destructiveForeground: '#220B12',
    border: '#203650',
    input: '#172942',
    success: '#5FE0A0',
    warning: '#FFC56B',
    high: '#FF986B',
    critical: '#FF6B8A',
    info: '#8EA8FF',
    overlay: '#0C182A',
  },
  radius: 18,
};

export default colors;
