/**
 * The console's information architecture (D32).
 *
 * One tree, filtered by role — subtraction only, never reordering. `member` sees the
 * Overview launcher and their own security; everyone else sees the administrative set.
 */
export const NAV = Object.freeze([
  { key: 'overview', label: 'Overview', href: '/', roles: ['owner', 'admin', 'auditor', 'member'] },
  { key: 'people', label: 'People', href: '/people', roles: ['owner', 'admin', 'auditor'] },
  { key: 'tools', label: 'Tools', href: '/tools', roles: ['owner', 'admin', 'auditor'] },
  { key: 'applications', label: 'Applications', href: '/applications', roles: ['owner', 'admin', 'auditor'] },
  { key: 'policy', label: 'Policy', href: '/policy', roles: ['owner', 'admin', 'auditor'] },
  { key: 'audit', label: 'Audit', href: '/audit', roles: ['owner', 'admin', 'auditor'] },
  { key: 'settings', label: 'Settings', href: '/settings', roles: ['owner', 'admin'] },
]);

export function navFor(role) {
  return NAV.filter((item) => item.roles.includes(role));
}

export function canSee(role, key) {
  const item = NAV.find((n) => n.key === key);
  return Boolean(item && item.roles.includes(role));
}

/** Write access per section. Everyone else in the section is read-only. */
export const WRITE_ROLES = Object.freeze({
  people: ['owner'],
  tools: ['owner', 'admin'],
  applications: ['owner', 'admin'],
  policy: ['owner', 'admin'],
  settings: ['owner'],
});

export function canWrite(role, key) {
  return (WRITE_ROLES[key] || []).includes(role);
}
