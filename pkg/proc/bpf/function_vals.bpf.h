// function_parameter stores information about a single parameter to a function.
typedef struct function_parameter {
      unsigned int offset; // offset from stack pointer.
      unsigned int size;   // size of the variable in bytes.
} function_parameter_t;

// function_parameter_list holds info about the function parameters and
// stores information on up to 8 parameters.
typedef struct function_parameter_list {
      unsigned int n_parameters;                   // number of parameters.
      function_parameter_t params[8];     // list of parameters.
} function_parameter_list_t;
