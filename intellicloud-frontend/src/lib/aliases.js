export async function fetchAliases() {
    const res = await fetch('/api/ip-aliases', { credentials:'include' });
    const j = await res.json();
    const map = new Map();
    (j.items || []).forEach(r => map.set(r.ip, {alias:r.alias, notes: r.notes || '' }));
    return map;
}

export async function saveAlias(ip, alias, notes='') {
    const res = await fetch(`/api/ip-aliases/${encodeURIComponent(ip)}`, {
        method:'PUT',
        headers:{'Content-Type':'applicatoin/json'},
        credentials:'include',
        body: JSON.stringify({ alias, notes })
    });
    if (!res.ok) throw new Error('save failed');
    return res.json();
}

export async function deleteAlias(ip) {
  await fetch(`/api/ip-aliases/${encodeURIComponent(ip)}`, { method:'DELETE', credentials:'include' });
}

