const store = require('../store')

function visibleTicket (req, res) {
  const ticket = store.tickets.get(Number(req.params.id))
  if (!ticket || ticket.orgId !== req.user.orgId) {
    res.status(404).json({ error: 'not found' })
    return null
  }
  return ticket
}

exports.list = (req, res) => {
  res.json([...store.tickets.values()].filter(t => t.orgId === req.user.orgId))
}

exports.create = (req, res) => {
  const ticket = store.addTicket({
    orgId: req.user.orgId,
    authorId: req.user.sub,
    title: String(req.body.title || '').slice(0, 200),
    body: String(req.body.body || '')
  })
  res.status(201).json(ticket)
}

exports.show = (req, res) => {
  const ticket = visibleTicket(req, res)
  if (ticket) res.json(ticket)
}

exports.update = (req, res) => {
  const ticket = visibleTicket(req, res)
  if (!ticket) return
  if (typeof req.body.title === 'string') ticket.title = req.body.title.slice(0, 200)
  if (typeof req.body.status === 'string') ticket.status = req.body.status
  store.record(ticket.id, req.user.sub, 'updated')
  res.json(ticket)
}

exports.remove = (req, res) => {
  const ticket = visibleTicket(req, res)
  if (!ticket) return
  store.tickets.delete(ticket.id)
  store.record(ticket.id, req.user.sub, 'deleted')
  res.status(204).end()
}

exports.history = (req, res) => {
  const events = store.history.filter(e => e.ticketId === Number(req.params.id))
  res.json(events)
}

exports.listComments = (req, res) => {
  const ticket = visibleTicket(req, res)
  if (ticket) res.json(store.comments.filter(c => c.ticketId === ticket.id))
}

exports.addComment = (req, res) => {
  const ticket = visibleTicket(req, res)
  if (!ticket) return
  const comment = store.addComment({
    ticketId: ticket.id,
    authorId: req.user.sub,
    body: String(req.body.body || '')
  })
  res.status(201).json(comment)
}

exports.showComment = (req, res) => {
  const comment = store.comments.find(c => c.id === Number(req.params.commentId))
  if (!comment) return res.status(404).json({ error: 'not found' })
  res.json(comment)
}
