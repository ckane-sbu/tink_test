

from absl import app, flags, logging
import tink
from tink import aead, cleartext_keyset_handle

FLAGS = flags.FLAGS

flags.DEFINE_enum('mode', None, ['generate', 'encrypt', 'decrypt'],
                  'The operation to perform.')
flags.DEFINE_string('keyset_path', None,
                    'Path to the keyset used for the encryption.')
flags.DEFINE_string('input_path', None, 'Path to the input file.')
flags.DEFINE_string('output_path', None, 'Path to the output file.')

def main(argv):
    del argv

    # Initialize Tink
    try:
        aead.register()
    except tink.TinkError as e:
        logging.error('Error initializing Tink: %s', e)
        return 1

    if FLAGS.mode == 'generate':
        # Generate a new keyset
        try:
            key_template = aead.aead_key_templates.AES128_GCM
            keyset_handle = tink.KeysetHandle.generate_new(key_template)
        except tink.TinkError as e:
            logging.exception('Error creating primitive: %s', e)
            return 1

        with open(FLAGS.keyset_path, 'wt') as keyset_file:
            try:
                cleartext_keyset_handle.write(tink.JsonKeysetWriter(keyset_file), keyset_handle)
            except tink.TinkError as e:
                logging.exception('Error writing key: %s', e)
                return 1
        return 0

    # Use the input keyset to encrypt/decrypt data

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
        logging.error('Error creating primitive: %s', e)
        return 1

    with open(FLAGS.input_path, 'rb') as input_file:
        input_data = input_file.read()
        if FLAGS.mode == 'decrypt':
            output_data = cipher.decrypt(input_data, b'envelope_example')
        elif FLAGS.mode == 'encrypt':
            output_data = cipher.encrypt(input_data, b'envelope_example')
        else:
            logging.error('Error mode not supported. Please choose "encrypt" or "decrypt".')
            return 1

        with open(FLAGS.output_path, 'wb') as output_file:
            output_file.write(output_data)

if __name__ == "__main__":
    flags.mark_flags_as_required(['mode', 'keyset_path'])
    app.run(main)
