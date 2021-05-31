from absl import app, flags, logging
import tink
from tink import aead, cleartext_keyset_handle

FLAGS = flags.FLAGS

flags.DEFINE_enum('mode', None, ['encrypt', 'decrypt'],
                  'The operation to perform.')
flags.DEFINE_string('keyset_path', None,
                    'Path to the keyset used for encryption.')
flags.DEFINE_string('input_path', None, 'Path to the input file.')
flags.DEFINE_string('output_path', None, 'Path to the output file.')
flags.DEFINE_string('associated_data', None,
                    'Optional associated data used for the encryption.')

def main(argv):
    del argv # Unused

    associated_data = b'' if not FLAGS.associated_data else bytes(FLAGS.associated_data, 'utf-8')

    #Initialize Tink
    try:
        aead.register()
    except tink.TinkError as e:
        logging.error('Error initializing Tink: %s', e)
        return 1

    # Read the keyset into a keyset_handle
    with open(FLAGS.keyset_path, 'rt') as keyset_file:
        try:
            text = keyset_file.read()
            keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(text))
        except tink.TinkError as e:
            logging.exception('Error reading key: %s', e)
            return 1

    # Get the primitive
    try:
        cipher = keyset_handle.primitive(aead.Aead)
    except tink.TinkError as e:
        logging.error('Error creating primitives: %s', e)
        return 1

    with open(FLAGS.input_path, 'rb') as input_file:
        input_data = input_file.read()
        if FLAGS.mode == 'decrypt':
            output_data = cipher.decrypt(input_data, associated_data)
        elif FLAGS.mode == 'encrypt':
            output_data = cipher.encrypt(input_data, associated_data)
        else:
            logging.error(
                'Error mode not supported. Please choose "encrypt" or "decrypt".')
            return 1

        with open(FLAGS.output_path, 'wb') as output_file:
            output_file.write(output_data)

    if __name__ == "__main__":
        flags.mark_flags_as_required([
            'mode', 'keyset_path', 'input_path', 'output_path'])
        app.run(main)
