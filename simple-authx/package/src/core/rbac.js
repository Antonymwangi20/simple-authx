export function requireRole(role) {
	return (req, res, next) => {
		const user = req.user || {};
		if (!user.role || user.role !== role) {
			return res.status(403).json({ error: 'Forbidden' });
		}
		next();
	};
}

export function requireAnyRole(roles = []) {
	return (req, res, next) => {
		const user = req.user || {};
		if (!user.role || !roles.includes(user.role)) {
			return res.status(403).json({ error: 'Forbidden' });
		}
		next();
	};
}
