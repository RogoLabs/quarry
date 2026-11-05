const express = require('express')
const auth = require('./middleware/auth')
const tickets = require('./routes/tickets')
const admin = require('./routes/admin')
const health = require('./routes/health')

const app = express()
app.use(express.json({ limit: '100kb' }))
app.use(auth.loadUser)

app.use('/api', tickets)
app.use('/api/admin', admin)
app.use('/', health)

if (require.main === module) {
  app.listen(process.env.PORT || 3000)
}

module.exports = app
