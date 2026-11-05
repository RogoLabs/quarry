const tickets = new Map()
const users = new Map()
const comments = []
const history = []
let nextId = 1

function addTicket (fields) {
  const ticket = { id: nextId++, status: 'open', ...fields }
  tickets.set(ticket.id, ticket)
  record(ticket.id, fields.authorId, 'created')
  return ticket
}

function addComment (fields) {
  const comment = { id: nextId++, createdAt: new Date().toISOString(), ...fields }
  comments.push(comment)
  record(fields.ticketId, fields.authorId, 'commented')
  return comment
}

function record (ticketId, actorId, action) {
  history.push({ ticketId, actorId, action, at: new Date().toISOString() })
}

module.exports = { tickets, users, comments, history, addTicket, addComment, record }
