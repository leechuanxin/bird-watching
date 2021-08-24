DROP TABLE IF EXISTS behaviours;
DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS notes_behaviours;
DROP TABLE IF EXISTS species;
DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS notes (
  id SERIAL PRIMARY KEY,
  created_date DATE,
  created_time TIME,
  last_updated_date DATE,
  last_updated_time TIME,
  date DATE,
  time TIME,
  duration_hour INTEGER,
  duration_minute INTEGER,
  duration_second INTEGER,
  number_of_birds INTEGER,
  flock_type TEXT,
  created_user_id INTEGER,
  species_id INTEGER
);

CREATE TABLE IF NOT EXISTS behaviours (
  id SERIAL PRIMARY KEY,
  name TEXT
);

CREATE TABLE IF NOT EXISTS notes_behaviours (
  id SERIAL PRIMARY KEY,
  note_id INTEGER,
  behaviour_id INTEGER
);

CREATE TABLE IF NOT EXISTS species (
  id SERIAL PRIMARY KEY,
  name TEXT,
  scientific_name TEXT
);

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT,
  password TEXT
);

INSERT INTO species (name, scientific_name) VALUES ('King Quail', 'Excalfactoria chinensis'),
  ('Red Junglefowl', 'Gallus gallus'),
  ('Wandering Whistling Duck', 'Dendrocygna arcuata'),
  ('Lesser Whistling Duck', 'Dendrocygna javanica'),
  ('Cotton Pygmy Goose', 'Nettapus coromandelianus'),
  ('Garganey', 'Spatula querquedula'),
  ('Northern Shoveler', 'Spatula clypeata'),
  ('Gadwall', 'Mareca strepera'),
  ('Eurasian Wigeon', 'Mareca penelope'),
  ('Northern Pintail', 'Anas acuta'),
  ('Tufted Duck', 'Aythya fuligula'),
  ('Malaysian Eared Nightjar', 'Lyncornis temminckii');

INSERT INTO behaviours (name) VALUES ('Walking'),
  ('Resting'),
  ('Gathering Nesting Materials'),
  ('Mobbing'),
  ('Long Song'),
  ('Bathing'),
  ('Preening'),
  ('Territory Defence'),
  ('Climbing Tree'),
  ('Bark Feeding'),
  ('Hunting'),
  ('Flying'),
  ('Ground Feeding'),
  ('Feeder Feeding'),
  ('Soaring'),
  ('Pecking'),
  ('Drinking'),
  ('Perched'),
  ('Flocking'),
  ('Hovering'),
  ('Caring For Young'),
  ('Pooping'),
  ('Nesting');