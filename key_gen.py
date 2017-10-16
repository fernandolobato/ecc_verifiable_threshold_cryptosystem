import os

from ecdsa.curves import SECP256k1
import threshold_cryptosystem as threshold

num_keys = 50
directory = 'keys/'

if not os.path.exists(directory):
    os.makedirs(directory)

s_keys = [threshold.generate_key() for i in range(num_keys)];
p_keys = list(map(lambda x: x * SECP256k1.generator , s_keys))


big_num = lambda num: 'new BigNumber(\'{}\')'.format(num)
stringify_point = lambda p: big_num(p.x()) + ',' + big_num(p.y())




open(os.path.join(directory, 'private.js'), 'w').write('var secKeys = [{}]'.format(''.join([ big_num(k) + ',' for k in s_keys])[:-1]))
open(os.path.join(directory, 'public.js'), 'w').write('var pubKeys = [{}]'.format(''.join([ '[{}],'.format(stringify_point(k)) for k in p_keys])[:-1]))

open(os.path.join(directory, 'private.txt'), 'w').write('{}'.format(''.join([ str(k) + '\n' for k in s_keys])))
open(os.path.join(directory, 'public.txt'), 'w').write('{}'.format(''.join([ '{},{}\n'.format(k.x(), k.y()) for k in p_keys])[:-1]))