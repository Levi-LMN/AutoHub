from PIL import Image, ImageDraw, ImageFont

# Create a blank 500x500 image
image = Image.new('RGB', (500, 500), color=(73, 109, 137))

# Load a font
# Specify the correct path to the font file on your system
font_path = '/path/to/your/font.ttf'
font_size = 15
font = ImageFont.truetype(font_path, font_size)

# Initialize ImageDraw
d = ImageDraw.Draw(image)

# Add text
text = 'January 13, Tuesday\nA calm, quiet day'

# Get text size using the ImageFont object
textwidth, textheight = d.textsize(text, font=font)

# Position the text at the center bottom
position = ((image.width - textwidth) / 2, image.height - textheight)
d.text(position, text, font=font, fill=(255, 255, 255))

# Save the image
image.save('text_image.png')
