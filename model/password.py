from datetime import datetime
from pathlib import Path

''' #Agora vamos criar uma classe para servir de base a todas as 
classes que representam tabelas em banco de dados para criar os 
métodos de save e get.'''

class BaseModel: 
    BASE_DIR = Path(__file__).resolve().parent.parent
    DB_DIR = BASE_DIR / 'db'

    def save(self):
        table_path = Path(self.DB_DIR / f'{self.__class__.__name__}.txt')
        if not table_path.exists():
            table_path.touch()

        with open(table_path, 'a') as arq:
            arq.write("|".join(list(map(str, self.__dict__.values()))))
            arq.write('\n')


    @classmethod #Crie agora o método get para buscar os dados do banco:
    def get(cls):
        table_path = Path(cls.DB_DIR / f'{cls.__name__}.txt')
        if not table_path.exists():
            table_path.touch()

        with open(table_path, 'r') as arq:
            x = arq.readlines()
        
        results = []

        atributos = vars(cls()).keys()

        for i in x:
            split_v = i.split('|')
            tmp_dict = dict(zip(atributos, split_v))
            results.append(tmp_dict)

        return results            
        

'''Em model/passwords.py crie uma model 
para representar uma “tabela no banco de dados”'''

class Password(BaseModel):
    def __init__(self, domain=None, password=None, expire=False):
        self.domain = domain
        self.password = password
        self.create_at = datetime.now().isoformat()
        self.expire = 1 if expire else 0
