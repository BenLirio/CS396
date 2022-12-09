import pickle
import os
from termcolor import colored
import argparse
import signal
import random


multiple_choice_questions = [
  [
    "A certain type of computer misuse that is against the law was detected coming from Bob’s password-protected account. Without any further evidence, is Bob liable or not, and why?",
    [
      "Yes. Because it turns out that Bob was using Bob1988 as his password.",
      "Yes. The computing system cannot distinguish between possible impersonation (e.g., being a victim of an attack) or delegation (e.g., sharing his password with his coworker).",
      "No. Since user authentication doesn’t imply identification, Bob carries no responsibility.",
      "It really depends on whether the misuse happened during office hours on not."
    ],
    1
  ],
  [
    """A password is a secret that can be both refreshed and shared: Users can change their passwords or willingly give them to their family or friends, if needed.
How does user authentication based on fingerprints compare with user authentication using the RSA token, with respect to the ability of the users to refresh or share their underlying secrets?

You may assume that the RSA token produces new pseudorandom tokencodes by repeatedly (i.e., every minute) applying SHA2 over the current tokencode, starting with an initial secret tokencode, or secret seed, that is hard coded in the token and also known to the user at the time of registration."""
,
    [
      "Tokencodes can be shared but cannot be refreshed, whereas fingerprints can be refreshed but cannot be shared.",
      "Tokencodes can be both refreshed and shared, but fingerprints can neither be refreshed nor shared.",
      "Both tokencodes and fingerprints can be both refreshed and shared.",
      "Neither tokencodes nor fingerprints can be refreshed but they can both be shared - fingerprints, at least theoretically, assuming some highly sophisticated technology..."
    ],
    3
  ],
  [
    "How does fingerprint-based biometric authentication compare with password-based authentication with respect to the ability of users to refresh or share their underlying secrets?",
    [
      "Passwords can be both refreshed and shared, but fingerprints can neither be refreshed nor shared.",
      "Neither passwords nor fingerprints can be refreshed but they can both be shared.",
      "Both passwords and fingerprints can be refreshed and shared.",
      "Passwords can be refreshed but they cannot be shared, whereas fingerprints cannot be refreshed but they can be shared."
    ],
    0
  ],
  [
    "What motivated the design of public-key encryption and digital signatures?",
    [
      "The need to devise post-quantum cryptographic solutions; instead of relying on the factoring assumption which is known to hold only in the classical computational model, the use of extensions of perfectly secure OTP schemes allows for security even in the quantum computational model.",
      "The need to strengthen the security provided by ciphers or MACs; instead of relying on the use of an imperfectly secure scheme (e.g., OTP or AES), computational problems that are impossible to solve were introduced, such as computing discrete logs and factoring.",
      "The need to implement what is known as hybrid encryption; instead of treating the problems of confidentiality and integrity as separate stand-alone problem, public keys allow us to address at once the problem of implementing a secure tunnel between two parties, wherein transmitted messages cannot be learned or maliciously altered.",
      "The need to increase the flexibility of a multi-user cryptographic system with respect to its key-management; instead of relying on session-specific shared secret keys, the use of user-specific public-key pairs removed the need for out-of-band secret communication in order to distribute shared secret keys."
    ],
    3
  ],
  [
    'What best describes the term "digital certificate"?',
    [
      'A digital certificate implements the abstract concept of a "digital envelop," wherein a sensitive piece of information (such as a user\'s public key) can be made publicly available such that the information cannot be later altered; that is, one commits to the authentic version of this information and no tampering is possible.',
      "In the three-party model for data-query authentication (a.k.a. DB-as-a-service authentication model), a digital certificate is nothing more than the computational proof that the untrusted responder server provides the user with, in order for the user to verify the validity of the received answer.",
      "Digital certificates constitute the prevalent way with which we implement today a public-key infrastructure, wherein users' public keys are verified to be the currently correct/valid ones via a (chain of) verified signature(s) while using minimal trust assumptions about certain users' public keys (e.g., certificate authorities).",
      "A digital certificate is simply a digitally signed message that is used by a browser to verify that domain name resolution has happened correctly, thus eliminating the possibility of IP spoofing attacks.",
    ],
    2
  ],
  [
    "What is a consequence of encrypting files prior to their upload to a cloud-storage provider that employs deduplication?",
    [
      "Independently of the type of the encryption, it removes vulnerabilities that exist due to the use of cryptographic hashing for concealing sensitive data.",
      "Independently of the type of the encryption, it destroys any storage benefits due to deduplication.",
      "Depending on the type of encryption, it may negate any integrity protections due to the use of cryptographic hashing.",
      "Depending on the type of the encryption, it may negate any storage benefits due to deduplication.",
    ],
    3
  ],
  [
    "How does protocol DNSSEC compare to ordinary DNS?",
    [
      "DNSSEC processes domain names in the hash SHA2-256 domain, thus withstanding zone enumeration attacks.",
      "DNSSEC has all DNS records individually signed by a corresponding authoritative DNS server (e.g., a TLD server responsible for a top-level domain zone), thus tolerating IP spoofing attacks.",
      "DNSSEC provides integrity proofs for the existence or non-existence of any queried domain name, thus allowing verified domain name resolution.",
      "DNSSEC employs secret-key and public-key cryptographic protections, thus withstanding Internet-scale DDoS attacks (such as the Dyn attack) even when orchestrated by a botnet of millions of hacked machines."
    ],
    1
  ],
  [
    "How does protocol NSEC compare to protocol DNSSEC?",
    [
      "NSEC makes zone enumeration attacks harder to launch.",
      "NSEC provides verifiable answers also for queried domain names that do not resolve to any IP addresses.",
      "NSEC prevents against tampering of also non-existing domain names.",
      "NSEC makes use of cryptographic hashing to withstand zone enumeration attacks."
    ],
    1
  ],
  [
    "Stevens has recently updated it user-authentication system by adopting the use of Honeywords and a remote, cloud-based, server as HoneyChecker. Due to a large-scale DDoS attack against the cloud provider hosting the HoneyChecker, Stevens operates for an entire weekend without access to this server. What best describes the security of Stevens’ authentication system during this period?",
    [
      "The security of the system is increased to higher levels than those provided by the system prior to the adoption of Honeywords, because the DDoS attack also prevents attackers from compromising the HoneyChecker. This is why Honeywords strictly improve security.",
      "The security of the system is reduced, falling back to the levels provided by the system prior to the adoption of Honeywords, because theft of password files can no longer be detected. This is why Honeywords strictly improve security.",
      "The security of the system remains at the same levels as those provided by the system prior to the adoption of Honeywords, because Steven's authentication service remains completely unavailable during the DDoS attack. This is why in the Honeyword system all CIA properties become relevant.",
      "The security of the system collapses to levels worse than those provided by the system prior to the adoption of Honeywords, because impersonation attacks now become feasible. This is why Honeywords assume the availability of the split-server architecture as a precondition.",
    ],
    1
  ],
  [
    "What are the three requirements, in principle, that a patent application should satisfy in order to be approved by a Patent Office?",
    [
      "The disclosed invention should be about a technical idea that 1) solves a problem, 2) is novel, or equivalently 'not obvious to those skilled in art,' and 3) can be implemented.",
      "The copyrighted material should be the expression of an idea that is 1) novel, 2) well documented by its author in some form, and 3) in case it is software, published in its source-code format.",
      "The disclosed idea should be an information that comprises 1) an intellectual property of a company, 2) a well-kept secret within the company, and 3) a competitive advantage of this company.",
      "The disclosed invention should be about a technical idea that 1) describes an algorithm, 2) has not published anywhere within the last 20 years, and 3) provides a company some competitive advantage.",
    ],
    0
  ],
  [
    "After uploading your presentation slides of your final project for CS306 on the course web page, you decide that the main technical idea in your project --- namely that in order to protect against SQL injections attacks, the reference monitor of a DBMS system should employ Honeywords for user authentication and MAC for access-control management --- can be the basis of very promising startup. Which existing legal protection(s) you can use to ensure that only you will  financially benefit by commercializing this idea?",
    [
      "You can copyright this idea.",
      "You can patent this idea.",
      "You can treat this idea as a trade secret.",
      "No legal protection can be applied for your idea.",
    ],
    3
  ],
  [
    """A research paper is submitted to a top security conference for publication. The paper presents results on a new powerful theoretical attack against a wide range of location-based services. To demonstrate its efficacy and practicality, the authors report on a real-world and fully-deployed version of the attack, orchestrated against the popular mobile application Waze, which provides users with real-time map routes and driving conditions. It is shown that, because Waze does not support any authenticated roadmap queries, it is possible to reroute users to fake (maliciously or randomly crafted) routes and notify them on fake (non-existing) road conditions. This actual attack was performed in a highly-controlled low-risk environment, in a rural area in upstate NY during the 48-hour span of a weekend, with a users body of only 100. Prior to the submission of the paper to the conference, the authors contacted Waze to inform them about the specific attack and the security issues their application has, and they are currently working with the Waze security personnel to add any necessary safeguards.

As a member of the Program Committee of the conference, which factors should you primarily consider in making an accept/reject decision?""",
    [
      "Intellectual merit and novelty. If the technical ideas underlying the discovery of the vulnerability and the orchestrated attack are novel, non-trivial and cryptographically interesting, the paper should be published.",
      "Safety and ethical considerations. Any paper demonstrating a real-world attack should be evaluated with respect to the risk its publication may impose to the public; here, since the authors provided Waze a timely notice and minimized the harm inflicted by the attack, their paper should be published - as long as, of course, it is technically correct and novel.",
      "Practicality and importance. Since the paper demonstrates a new vulnerability that can be easily be exploited to negatively affect many location-based applications and millions of users, it is worth being published.",
      "Scientific merits and ethical considerations. Any type of research should constitute a scientifically solid contribution that is performed in an ethical manner, especially when it involves an real-world attack; here, independently of the merits of the results, the method used for demonstrating the attack is clearly unethical (and dangerous at least)."
    ],
    3
  ],
  [
    "In one CS396 lab, you need to perform some web search in one of the provided computer desktops. When you start working on the computer, you realize that your classmate Alice from the previous lab session is still logged in her Gmail account, as the web browser opens at a tab where you can see her emails. What is the most ethical thing to do?",
    [
      "You should use your hacking tricks to delete the web browser from the computer.",
      "You should work on a new tab.",
      "You should immediately logout of her Gmail account and reboot the machine or re-launch the Web browser application.",
      "You should check to see if she has received the grade for her midterm exam, which you still wait to learn."
    ],
    2
  ],
  [
    "In a buffer-overflow attack, what is the most challenging phase for the attacker who has already identified that a target server runs software with a buffer-overflow vulnerability?",
    [
      "To inject the malicious code.",
      "To evade detection that a buffer-overflow attack occurs.",
      "To translate the malicious code into the high-level language used to implement the vulnerable software.",
      "To ensure that the injected malicious code will eventually run."
    ],
    3
  ],
  [
    "In a buffer-overflow attack, what is the most challenging phase for the attacker and why?",
    [
      "To inject the malicious code. Buffer overflow opportunities are hard to find, as developers become more and more skillful to avoid them.",
      "To translate a meaningful malicious code, written in programming language X, into the specific high-level programming language Y that is used by the target program. A typical malware requires sophisticated math to break cryptography, therefore the corresponding codes in languages X and Y are generally long and tedious to carefully translate to each other.",
      "To evade detection that a buffer-overflow attack occurs. Such an attack is typically the very first step of a sophisticated Advanced Persistent Threat type of cyberattack, so it is crucial for the attacker to conceal its actions.",
      "To ensure that the injected malicious code will eventually run. Indeed, the attacker cannot know with certainty the absolute memory locations of the injected overflowed data; this is where the attacker needs lots of trial and error and 'nopsled' techniques."
    ],
    3
  ]

]


#multiple_choice_questions = []
#for i in range(10):
#  multiple_choice_questions.append([
#    f'{i}',
#    [
#      'Ok',
#      'error'
#    ],
#    0
#  ])

history = []


def load_history():
  try:
    with open('history.pkl', 'rb') as f:
      return pickle.load(f)
  except:
    return history

def save_history(history):
  with open('history.pkl', 'wb') as f:
    pickle.dump(history, f)

def handler(signum, frame):
  save_history(history)
  exit(0)

signal.signal(signal.SIGINT, handler)


def get_question():
  mcqs_keys = list(map(lambda x: x[0], multiple_choice_questions))
  mcqs_times_asked = {}
  for mcq in mcqs_keys:
    mcqs_times_asked[mcq] = 0
  mcqs_times_correct = {}
  for mcq in mcqs_keys:
    mcqs_times_correct[mcq] = 0
  mcqs_map = {}
  for mcq in multiple_choice_questions:
    mcqs_map[mcq[0]] = mcq
  mcqs_priority = {}
  for mcq_key in mcqs_keys:
    mcqs_priority[mcq_key] = 0
  mcqs_last_asked = {}
  for mcq_key in mcqs_keys:
    mcqs_last_asked[mcq_key] = -1

  for i in range(len(history)):
    [mcq_key, correct] = history[i]
    mcqs_last_asked[mcq_key] = i
    mcqs_times_asked[mcq_key] += 1
    if correct:
      mcqs_times_correct[mcq_key] += 1
      mcqs_priority[mcq_key] -= 1
    else:
      mcqs_priority[mcq_key] += 1

  mcqs_data = []
  for mcq_key in mcqs_keys:
    mcqs_data.append([
      mcqs_priority[mcq_key],
      mcqs_last_asked[mcq_key],
      mcq_key
    ])

  # dont ask questions that were asked less than 5 questions ago
  possible_questions = list(filter(lambda x: (len(history) - x[1] > 3) or x[1] == -1, mcqs_data))
  if len(possible_questions) == 0:
    possible_questions = mcqs_data # fallback to all questions
  
  possible_questions.sort(key=lambda x: x[0], reverse=True)

  [mcq_priority, last_asked, mcq_key] = possible_questions[0]
  times_asked = mcqs_times_asked[mcq_key]
  times_correct = mcqs_times_correct[mcq_key]
  if last_asked == -1:
    print(f'DEBUG: [priority={mcq_priority}] [last_asked=never] [score={times_correct}/{times_asked}]')
  else:
    print(f'DEBUG: [priority={mcq_priority}] [last_asked={len(history) - last_asked}] [score={times_correct}/{times_asked}]')
  return mcqs_map[mcq_key]

def as_int(s):
  try:
    return int(s)
  except:
    return -1

def practice_loop():
  [question, options, correct] = get_question()
  shuffled_options = options.copy()
  random.shuffle(shuffled_options)
  shuffled_correct = -1
  for i in range(len(shuffled_options)):
    if shuffled_options[i] == options[correct]:
      shuffled_correct = i
      break
  

  print(f'\n{question}\n')
  for i in range(len(shuffled_options)):
    print(f'{i+1}) {shuffled_options[i]}')
  while True:
    user_answer = as_int(input('Your answer: '))
    if user_answer in range(1, len(shuffled_options) + 1):
      break
    else:
      print(f'Invalid response. Input a number between 1 and {len(shuffled_options)+1}')
  ok = shuffled_correct == user_answer - 1
  if ok:
    print(colored('Correct!', 'green'))
    input('Press enter to continue...')
  else:
    print(colored('Incorrect!', 'red'))
    reveal = input('Reveal answer [y/N]? ')
    if reveal == 'y':
      print(f'\n{shuffled_options[shuffled_correct]}\n')
      input('Press enter to continue...')
  os.system('clear')
  history.append([ question, ok ])
  practice_loop()

def reset_history():
  save_history([])
  print('History reset.')

def show_stats():
  num_total = len(history)
  num_correct = len(list(filter(lambda x: x[1], history)))
  print(f'You have answered {num_correct} out of {num_total} questions correctly.')

if __name__ == '__main__':
  parser = argparse.ArgumentParser(
    prog='practice',
    description='A program to help you study for the 396 final.',
    epilog='Good luck!'
  )
  parser.add_argument('--reset', action='store_true', help='Reset your history')
  parser.add_argument('--stats', action='store_true', help='Show your stats')
  parser.add_argument('--practice', action='store_true', help='Practice mode')

  args = parser.parse_args()
  history = load_history()

  if args.reset:
    reset_history()
  if args.stats:
    show_stats()
  if args.practice:
    practice_loop()
  if not args.reset and not args.stats and not args.practice:
    parser.print_help()
