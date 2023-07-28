const path = require('path')
const config = require('./webpack.config.js')

config.devServer = {
  historyApiFallback: true,
  port: 8080
}

config.devtool = 'inline-source-map'

module.exports = config
