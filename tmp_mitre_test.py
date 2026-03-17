from mitre_mapper import map_attack_to_mitre
cases = [
 ('PATH_TRAVERSAL','../../../etc/passwd','tester'),
 ('CMD_INJECTION',';ls -la','tester'),
 ('SSRF','http://localhost:8080/admin','tester'),
 ('Insecure Deserialization','pickle.loads(data)','tester'),
 ('SQL Injection','" OR 1=1','tester'),
 ('XSS','<script>alert(1)</script>','tester')
]
for name,payload,att in cases:
    m = map_attack_to_mitre(name,payload,att)
    print(name, payload, '->', [(x.technique.technique_id, x.technique.name, x.confidence) for x in m])
