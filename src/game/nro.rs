// fighter nro name -> display name. anything not listed (common, items, stages) gets skipped
fn fighter_display(nro_name: &str) -> Option<&'static str> {
    Some(match nro_name {
        "mario" => "Mario", "donkey" => "Donkey Kong", "link" => "Link",
        "samus" => "Samus", "samusd" => "Dark Samus", "yoshi" => "Yoshi",
        "kirby" => "Kirby", "fox" => "Fox", "pikachu" => "Pikachu",
        "luigi" => "Luigi", "ness" => "Ness", "captain" => "Captain Falcon",
        "purin" => "Jigglypuff", "peach" => "Peach", "daisy" => "Daisy",
        "koopa" => "Bowser", "sheik" => "Sheik", "zelda" => "Zelda",
        "mariod" => "Dr. Mario", "pichu" => "Pichu", "falco" => "Falco",
        "marth" => "Marth", "lucina" => "Lucina", "younglink" => "Young Link",
        "ganon" => "Ganondorf", "mewtwo" => "Mewtwo", "roy" => "Roy",
        "chrom" => "Chrom", "gamewatch" => "Mr. Game & Watch",
        "metaknight" => "Meta Knight", "pit" => "Pit", "pitb" => "Dark Pit",
        "szerosuit" => "Zero Suit Samus", "wario" => "Wario",
        "snake" => "Snake", "ike" => "Ike",
        "pzenigame" => "PT Squirtle", "pfushigisou" => "PT Ivysaur",
        "plizardon" => "PT Charizard",
        "diddy" => "Diddy Kong", "lucas" => "Lucas", "sonic" => "Sonic",
        "dedede" => "King Dedede", "pikmin" => "Olimar", "lucario" => "Lucario",
        "robot" => "R.O.B.", "toonlink" => "Toon Link", "wolf" => "Wolf",
        "murabito" => "Villager", "rockman" => "Mega Man",
        "wiifit" => "Wii Fit Trainer", "rosetta" => "Rosalina & Luma",
        "littlemac" => "Little Mac", "gekkouga" => "Greninja",
        "palutena" => "Palutena", "pacman" => "Pac-Man", "reflet" => "Robin",
        "shulk" => "Shulk", "koopajr" => "Bowser Jr.",
        "duckhunt" => "Duck Hunt", "ryu" => "Ryu", "ken" => "Ken",
        "cloud" => "Cloud", "kamui" => "Corrin", "bayonetta" => "Bayonetta",
        "inkling" => "Inkling", "ridley" => "Ridley", "simon" => "Simon",
        "richter" => "Richter", "krool" => "King K. Rool",
        "shizue" => "Isabelle", "gaogaen" => "Incineroar",
        "miifighter" => "Mii Brawler", "miiswordsman" => "Mii Swordfighter",
        "miigunner" => "Mii Gunner", "popo" => "Ice Climbers",
        "packun" => "Piranha Plant", "jack" => "Joker", "brave" => "Hero",
        "buddy" => "Banjo & Kazooie", "dolly" => "Terry", "master" => "Byleth",
        "tantan" => "Min Min", "pickel" => "Steve", "edge" => "Sephiroth",
        "eflame" => "Pyra", "elight" => "Mythra", "demon" => "Kazuya",
        "trail" => "Sora",
        _ => return None,
    })
}

fn nro_load(info: &skyline::nro::NroInfo) {
    if let Some(_display) = fighter_display(info.name) {
    }
}

pub fn install() {
    skyline::nro::add_hook(nro_load).ok();
}
