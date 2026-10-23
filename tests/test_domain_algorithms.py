import unittest, tempfile, contextlib, io
from pathlib import Path
from test_domain_generator import load, ROOT

class AlgorithmTests(unittest.TestCase):
    def test_selected_algorithms(self):
        g=load(ROOT/'generator.py')
        domain={'title':'Demo','record_name':'report','fields':[{'name':'name','type':'text','search':True}], 'min_records':1}
        configurations=[('AES-128','SHA-256','RSA','RSA','SSE'),('DES','MD5','ECDH','Schnorr','PKSE'),('Triple-DES','SHA-1','RSA','ElGamal','SSE'),('AES-192','SHA-512','ECDH','RSA','PKSE')]
        for encryption,hashing,key,signature,search in configurations:
            with self.subTest(encryption=encryption), tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
                algorithms=dict(encryption=encryption,hash=hashing,key=key,signature=signature,search=search)
                file=g.create_domain_solution(domain,{'Owner':list(g.DOMAIN_ACTIONS)},Path(tmp)/'out',algorithms=algorithms)
                m=load(file);m.new_password=lambda label:'password';m.setup();m.ROLE='Owner'
                self.assertEqual(m.ALGORITHMS,algorithms)
                m.submit_record('R1',{'name':'Alice'})
                self.assertTrue(m.verify_record('R1'))
                self.assertEqual(m.find_records('name','alice'),['R1'])
                self.assertEqual(m.find_records('name','bob'),[])
                m=load(file);m.ROLE='Owner'
                self.assertEqual(m.view_record('R1'),{'name':'Alice'})
                digest=m.hash_message('test'); private,public=m.generate_signing_keys()
                sig=m.sign_hash(digest,private,public)
                self.assertTrue(m.verify_signature(digest,sig,public))
                self.assertFalse(m.verify_signature(m.hash_message('changed'),sig,public))
                m.aggregate_records();m.getpass=lambda prompt:'password';m.threshold_decrypt()

    def test_choices(self):
        g=load(ROOT/'generator.py')
        with self.assertRaises(ValueError):g.validate_algorithms({'hash':'unknown'})
        answers=iter(['AES-192','SHA-256','ECDH','RSA','PKSE'])
        g.input=lambda prompt:next(answers)
        self.assertEqual(g.choose_algorithms()['search'],'PKSE')
