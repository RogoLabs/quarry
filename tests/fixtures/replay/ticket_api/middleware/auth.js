const jwt = require('jsonwebtoken')

function loadUser (req, res, next) {
  const header = req.get('authorization') || ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : null
  req.user = null
  if (token) {
    try {
      req.user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] })
    } catch (err) {
      req.user = null
    }
  }
  next()
}

function requireUser (req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'login required' })
  next()
}

function requireAdmin (req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'admin only' })
  }
  next()
}

module.exports = { loadUser, requireUser, requireAdmin }
