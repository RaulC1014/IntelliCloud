function nsKey(uid) {
  return `ic.aliases.v1:${uid || 'anon'}`;
}

export function loadAliases(uid) {
    try{
        const raw = localStorage.getItem(nsKey(uid));
        const obj = raw ? JSON.parse(raw) : {};
        const m = new Map();
        Object.entries(obj).forEach(([ip, v]) => m.set(ip, { alias: v.alias, notes: v.notes || '' }));
        return m;
    } catch {
        return new Map();
    }
}

export function saveAlias(uid, ip, alias, notes = '') {
  const key = nsKey(uid);
  const raw = localStorage.getItem(key);
  const obj = raw ? JSON.parse(raw) : {};
  if (!alias || !alias.trim()) {
    delete obj[ip];
  } else {
    obj[ip] = { alias: alias.trim(), notes };
  }
  localStorage.setItem(key, JSON.stringify(obj));
}

export function deleteAlias(uid, ip) {
    const key = nsKey(uid);
    const raw = localStorage.getItem(key);
    const obj = raw ? JSON.parse(raw) : {};
    delete obj[ip];
    localStorage.setItem(key, JSON.stringify(obj));
}