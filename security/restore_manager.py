import shutil

def restore_file(file_path, original_path):
    """
    Restaura um arquivo da quarentena ou de backup.
    """
    shutil.move(file_path, original_path)