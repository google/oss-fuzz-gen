'''
customed prompting for GPT-4 by using spec.
'''

import os

from openai import OpenAI

GPT_MODEL = "gpt-4-1106-preview"

client = OpenAI(organization=os.getenv("OPENAI_ORG"),)


def chat_with_gpt(conversation_history, user_input, json=True):
  '''
    Chat with the GPT model, and return the AI response.

    @conversation_history: a list of dict, each dict has two keys: role, content
    @user_input: a string
    '''

  # Call the OpenAI API
  msg = conversation_history
  msg.append({
      "role": "user",
      "content": user_input,
  })

  model_config = {'temperature': 0.4, 'messages': msg, 'model': GPT_MODEL}

  if json:
    model_config['response_format'] = {"type": "json_object"}

  # print("model_config)", model_config)

  chat_completion = client.chat.completions.create(**model_config)
  token_used = chat_completion.usage
  ai_text = chat_completion.choices[0].message.content
  # Extract the response text

  # Update the conversation history
  msg.append({
      "role": "assistant",
      "content": ai_text,
  })

  return ai_text, msg, token_used
