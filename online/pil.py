from PIL import Image

def crop_image_to_focus(filepath, output_path, crop_box=None):
    img = Image.open(filepath)
    if crop_box:
        cropped_img = img.crop(crop_box)  
    else:
        width, height = img.size
        cropped_img = img.crop((0, 0, width, min(height, width))) 
    cropped_img.save(output_path)
