const store = require('../store')

const ROLES = new Set(['member', 'agent', 'admin'])

exports.listUsers = (req, res) => {
  res.json([...store.users.values()].map(u => ({ id: u.id, name: u.name, role: u.role })))
}

exports.disableUser = (req, res) => {
  const user = store.users.get(Number(req.params.id))
  if (!user) return res.status(404).json({ error: 'not found' })
  user.disabled = true
  res.json({ id: user.id, disabled: true })
}

exports.setRole = (req, res) => {
  const user = store.users.get(Number(req.params.id))
  if (!user) return res.status(404).json({ error: 'not found' })
  if (!ROLES.has(req.body.role)) return res.status(400).json({ error: 'bad role' })
  user.role = req.body.role
  res.json({ id: user.id, role: user.role })
}

exports.deleteUser = (req, res) => {
  if (!store.users.delete(Number(req.params.id))) {
    return res.status(404).json({ error: 'not found' })
  }
  res.status(204).end()
}
