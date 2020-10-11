example
=======


proxy1host -> proxy2host -> targethost 
```bash
PRIVATEKEY=$(cat ~/.ssh/id_rsa) HOST=proxy1host:22 SSHUSER=$USER COMMAND="ssh -A proxy2host ssh -A targethost hostname" ./exampleClient`
```
