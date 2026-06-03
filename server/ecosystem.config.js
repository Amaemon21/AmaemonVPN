module.exports = {
  apps: [{
    name: 'amaeonvpn',
    script: 'server.js',
    cwd: '/var/www/amaemonvpn/server',
    env: {
      SERVER_IP: '31.172.77.46',
      SERVER_PORT: '443',
      REALITY_SHORT_ID: '2eb34e487afa3a6f',
      XRAY_CONFIG_PATH: '/usr/local/etc/xray/config.json',
      REALITY_PUBLIC_KEY: 'JiKzwB-oCPDIPz9AuJH6uqg4AXAlphULHNdTPWj7tX0'
    }
  }]
}
